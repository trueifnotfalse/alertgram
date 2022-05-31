package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metricsmiddleware "github.com/slok/go-http-metrics/middleware"
	metricsmiddlewarestd "github.com/slok/go-http-metrics/middleware/std"

	"github.com/slok/alertgram/internal/deadmansswitch"
	"github.com/slok/alertgram/internal/forward"
	internalhttp "github.com/slok/alertgram/internal/http"
	"github.com/slok/alertgram/internal/http/alertmanager"
	"github.com/slok/alertgram/internal/log"
	"github.com/slok/alertgram/internal/log/logrus"
	metricsprometheus "github.com/slok/alertgram/internal/metrics/prometheus"
	"github.com/slok/alertgram/internal/notify"
	"github.com/slok/alertgram/internal/notify/telegram"
)

// Main is the main application.
type Main struct {
	cfg    *Config
	logger log.Logger
}

// Run runs the main application.
func (m *Main) Run() error {
	// Initialization and setup.
	var err error
	m.cfg, err = NewConfig()
	if err != nil {
		return err
	}
	m.logger = logrus.New(m.cfg.DebugMode).WithValues(log.KV{"version": Version})

	// Dependencies.
	metricsRecorder := metricsprometheus.New(prometheus.DefaultRegisterer)

	// Select the kind of template renderer: default or custom template.
	var tmplRenderer notify.TemplateRenderer
	if m.cfg.NotifyTemplate != nil {
		tmpl, err := ioutil.ReadAll(m.cfg.NotifyTemplate)
		if err != nil {
			return err
		}
		_ = m.cfg.NotifyTemplate.Close()
		tmplRenderer, err = notify.NewHTMLTemplateRenderer(string(tmpl))
		if err != nil {
			return err
		}
		tmplRenderer = notify.NewMeasureTemplateRenderer("custom", metricsRecorder, tmplRenderer)
		m.logger.Infof("using custom template at %s", m.cfg.NotifyTemplate.Name())
	} else {
		tmplRenderer = notify.NewMeasureTemplateRenderer("default", metricsRecorder, notify.DefaultTemplateRenderer)
	}

	var notifier forward.Notifier
	if m.cfg.NotifyDryRun {
		notifier = notify.NewLogger(tmplRenderer, m.logger)
	} else {
		tgCli, err := tgbotapi.NewBotAPI(m.cfg.TeletramAPIToken)
		if err != nil {
			return err
		}

		notifier, err = telegram.NewNotifier(telegram.Config{
			TemplateRenderer:      tmplRenderer,
			Client:                tgCli,
			DefaultTelegramChatID: m.cfg.TelegramChatID,
			Logger:                m.logger,
		})
		if err != nil {
			return err
		}
	}
	notifier = forward.NewMeasureNotifier(metricsRecorder, notifier)

	var g run.Group

	// Alertmanager webhook server.
	{

		// Alert forward.
		forwardSvc, err := forward.NewService(forward.ServiceConfig{
			AlertLabelChatID:               m.cfg.AlertLabelChatID,
			AlertAmountInOneMessage:        m.cfg.AlertAmountInOneMessage,
			TelegramTimeoutBetweenMessages: m.cfg.TelegramTimeoutBetweenMessages,
			Notifiers:                      []forward.Notifier{notifier},
			Logger:                         m.logger,
		})
		if err != nil {
			return err
		}
		forwardSvc = forward.NewMeasureService(metricsRecorder, forwardSvc)

		// Dead man's switch.
		ctx, ctxCancel := context.WithCancel(context.Background())
		var deadMansSwitchSvc deadmansswitch.Service = deadmansswitch.DisabledService // By default disabled.
		if m.cfg.DMSEnable {
			deadMansSwitchSvc, err = deadmansswitch.NewService(ctx, deadmansswitch.Config{
				CustomChatID: m.cfg.DMSChatID,
				Notifiers:    []forward.Notifier{notifier},
				Interval:     m.cfg.DMSInterval,
				Logger:       m.logger,
			})
			if err != nil {
				ctxCancel()
				return err
			}

			deadMansSwitchSvc = deadmansswitch.NewMeasureService(metricsRecorder, deadMansSwitchSvc)
		}

		// API server.
		logger := m.logger.WithValues(log.KV{"server": "alertmanager-handler"})
		h, err := alertmanager.NewHandler(alertmanager.Config{
			Debug:                 m.cfg.DebugMode,
			MetricsRecorder:       metricsRecorder,
			WebhookPath:           m.cfg.AlertmanagerWebhookPath,
			DeadMansSwitchService: deadMansSwitchSvc,
			DeadMansSwitchPath:    m.cfg.AlertmanagerDMSPath,
			ForwardService:        forwardSvc,
			Logger:                logger,
		})
		if err != nil {
			ctxCancel()
			return err
		}
		server, err := internalhttp.NewServer(internalhttp.Config{
			Handler:       h,
			ListenAddress: m.cfg.AlertmanagerListenAddr,
			Logger:        logger,
		})
		if err != nil {
			ctxCancel()
			return err
		}

		g.Add(
			func() error {
				return server.ListenAndServe()
			},
			func(_ error) {
				ctxCancel()
				if err := server.DrainAndShutdown(); err != nil {
					logger.Errorf("error while draining connections")
				}
			})
	}

	// Metrics.
	{
		logger := m.logger.WithValues(log.KV{"server": "metrics"})
		mux := http.NewServeMux()
		mux.Handle(m.cfg.MetricsPath, promhttp.Handler())
		mux.Handle(m.cfg.MetricsHCPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) }))
		mdlw := metricsmiddleware.New(metricsmiddleware.Config{Service: "metrics", Recorder: metricsRecorder})
		h := metricsmiddlewarestd.Handler("", mdlw, mux)
		server, err := internalhttp.NewServer(internalhttp.Config{
			Handler:       h,
			ListenAddress: m.cfg.MetricsListenAddr,
			Logger:        logger,
		})
		if err != nil {
			return err
		}

		g.Add(
			func() error {
				return server.ListenAndServe()
			},
			func(_ error) {
				if err := server.DrainAndShutdown(); err != nil {
					logger.Errorf("error while draining connections")
				}
			})
	}

	// Capture signals.
	{
		logger := m.logger.WithValues(log.KV{"service": "main"})
		sigC := make(chan os.Signal, 1)
		exitC := make(chan struct{})
		signal.Notify(sigC, syscall.SIGTERM, syscall.SIGINT)
		g.Add(
			func() error {
				select {
				case <-sigC:
					logger.Infof("signal captured")
				case <-exitC:
				}
				return nil
			},
			func(_ error) {
				close(exitC)
			})
	}

	return g.Run()
}

func main() {
	m := Main{}
	if err := m.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error running the app: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("goodbye!")
}
