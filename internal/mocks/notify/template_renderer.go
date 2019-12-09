// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	context "context"

	model "github.com/slok/alertgram/internal/model"
	mock "github.com/stretchr/testify/mock"
)

// TemplateRenderer is an autogenerated mock type for the TemplateRenderer type
type TemplateRenderer struct {
	mock.Mock
}

// Render provides a mock function with given fields: ctx, ag
func (_m *TemplateRenderer) Render(ctx context.Context, ag *model.AlertGroup) (string, error) {
	ret := _m.Called(ctx, ag)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, *model.AlertGroup) string); ok {
		r0 = rf(ctx, ag)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *model.AlertGroup) error); ok {
		r1 = rf(ctx, ag)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}