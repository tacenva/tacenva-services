package health

import (
	"context"

	"github.com/tacenva/tacenva-services/app"
)

type Service struct {
	appDeps *app.Deps
	context *app.Context
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
) *Service {
	return &Service{
		appDeps: appDeps,
		context: context,
	}
}

func (s *Service) IsReachable() bool {
	if !s.context.IsRemote {
		return false
	}

	return s.appDeps.Client.IsReachable(
		s.context.SelectedSot.Address,
	)
}

func (s *Service) CheckReachabilityContext(ctx context.Context) {
	if !s.context.IsRemote {
		s.appDeps.Client.SetReachable(
			s.context.SelectedSot.Address,
			false,
		)
		return
	}

	s.appDeps.Client.CheckReachabilityContext(
		ctx,
		s.context.SelectedSot.Address,
	)
}
