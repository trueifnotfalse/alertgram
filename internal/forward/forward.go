package forward

import (
	"context"
	"errors"
	"fmt"
	"github.com/slok/alertgram/internal/internalerrors"
	"github.com/slok/alertgram/internal/log"
	"github.com/slok/alertgram/internal/model"
	"time"
)

// Properties are the  properties an AlertGroup can have
// when the forwarding process is done.
type Properties struct {
	// CustomChatID can be used when the forward should be done
	// to a different target (chat, group, channel, user...)
	// instead of using the default one.
	CustomChatID string
}

// Service is the domain service that forwards alerts
type Service interface {
	// Forward knows how to forward alerts from an input to an output.
	Forward(ctx context.Context, props Properties, alertGroup *model.AlertGroup) error
}

// ServiceConfig is the service configuration.
type ServiceConfig struct {
	AlertLabelChatID               string
	AlertAmountInOneMessage        int
	TelegramTimeoutBetweenMessages time.Duration
	Notifiers                      []Notifier
	Logger                         log.Logger
}

func (c *ServiceConfig) defaults() error {
	if len(c.Notifiers) == 0 {
		return errors.New("notifiers can't be empty")
	}

	if c.Logger == nil {
		c.Logger = log.Dummy
	}

	return nil
}

type service struct {
	cfg       ServiceConfig
	notifiers []Notifier
	logger    log.Logger
}

// NewService returns a new forward.Service.
func NewService(cfg ServiceConfig) (Service, error) {
	err := cfg.defaults()
	if err != nil {
		err := fmt.Errorf("%w: %s", internalerrors.ErrInvalidConfiguration, err)
		return nil, fmt.Errorf("could not create forward service instance because invalid configuration: %w", err)
	}

	return &service{
		cfg:       cfg,
		notifiers: cfg.Notifiers,
		logger:    cfg.Logger.WithValues(log.KV{"service": "forward.Service"}),
	}, nil
}

var (
	// ErrInvalidAlertGroup will be used when the alertgroup is not valid.
	ErrInvalidAlertGroup = errors.New("invalid alert group")
)

func (s service) Forward(ctx context.Context, props Properties, alertGroup *model.AlertGroup) error {
	// TODO(slok): Add better validation.
	if alertGroup == nil {
		return fmt.Errorf("alertgroup can't be empty: %w", ErrInvalidAlertGroup)
	}

	notifications, err := s.createNotifications(props, alertGroup)
	if err != nil {
		return fmt.Errorf("could not prepare notifications from the alerts: %w", err)
	}

	// TODO(slok): Add concurrency using workers.
	for _, notifier := range s.notifiers {
		for _, notification := range notifications {
			err := notifier.Notify(ctx, *notification)
			if err != nil {
				s.logger.WithValues(log.KV{"notifier": notifier.Type(), "alertGroupID": alertGroup.ID, "chatID": notification.ChatID}).
					Errorf("could not notify alert group: %s", err)
			}
			if s.cfg.TelegramTimeoutBetweenMessages > 0 {
				time.Sleep(s.cfg.TelegramTimeoutBetweenMessages)
			}
		}
	}

	return nil
}

func (s service) createNotifications(props Properties, alertGroup *model.AlertGroup) (ns []*Notification, err error) {
	alertsGroupedByChatId := s.groupAlertsByChatId(alertGroup)

	// Create notifications based on the alertgroups.
	var notifications []*Notification
	for chatID, alertList := range *alertsGroupedByChatId {
		var alerts []model.Alert
		count := 0
		for _, alert := range *alertList {
			alerts = append(alerts, alert)
			count++
			if count < s.cfg.AlertAmountInOneMessage {
				continue
			}
			notification := s.createNotification(chatID, &props, alertGroup, &alerts)
			notifications = append(notifications, notification)
			alerts = nil
			count = 0
		}
		if 0 < len(alerts) {
			notification := s.createNotification(chatID, &props, alertGroup, &alerts)
			notifications = append(notifications, notification)
		}
	}

	return notifications, nil
}

func (s service) createNotification(chatId string, props *Properties, alertGroup *model.AlertGroup, alerts *[]model.Alert) *Notification {
	id := alertGroup.ID
	if chatId != "" {
		id = fmt.Sprintf("%s-%s", alertGroup.ID, chatId)
	} else {
		chatId = props.CustomChatID
	}
	ag := &model.AlertGroup{
		ID:     id,
		Labels: alertGroup.Labels,
		Alerts: *alerts,
	}

	return &Notification{
		AlertGroup: *ag,
		ChatID:     chatId,
	}
}

func (s service) groupAlertsByChatId(alertGroup *model.AlertGroup) *map[string]*[]model.Alert {
	alertListByChatID := map[string]*[]model.Alert{}
	for _, a := range alertGroup.Alerts {
		chatID := a.Labels[s.cfg.AlertLabelChatID]
		alertList, ok := alertListByChatID[chatID]
		if !ok {
			alertList = &([]model.Alert{})
		}
		*alertList = append(*alertList, a)
		alertListByChatID[chatID] = alertList
	}

	return &alertListByChatID
}
