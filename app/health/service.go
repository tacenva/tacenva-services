package health

import (
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

	return s.appDeps.Client.IsReachable()
}

func (s *Service) CheckReachability() {
	if !s.context.IsRemote {
		s.appDeps.Client.SetReachable(false)
		return
	}

	s.appDeps.Client.CheckReachability(
		s.context.SelectedSot.Address,
	)
}
