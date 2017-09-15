package mocks

//go:generate mockgen -destination mocks_fc/flow_control_manager.go -package mocks_fc github.com/phuslu/quic-go/internal/flowcontrol FlowControlManager
//go:generate mockgen -destination cpm.go -package mocks github.com/phuslu/quic-go/handshake ConnectionParametersManager
