package vm

import (
	"context"
	"fmt"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/exitcode"
	"github.com/filecoin-project/lotus/chain/actors/aerrors"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/filecoin-project/lotus/chain/actors/builtin/reward"
	"github.com/filecoin-project/lotus/chain/types"
	"go.opencensus.io/trace"
	"golang.org/x/xerrors"
	"time"
)

func HandleMultiMsg(vm *VM, ctx context.Context, cmsg *types.MultiMsg, span *trace.Span, start time.Time)  (*ApplyRet, error) {

	msg := cmsg.VMMessage()
	if span.IsRecordingEvents() {
		span.AddAttributes(
			//TODO
			trace.StringAttribute("to", msg.To.String()),
			trace.Int64Attribute("method", int64(msg.Method)),
			trace.StringAttribute("value", msg.Value.String()),
		)
	}

	if err := checkMessage(msg); err != nil {
		//return nil, err
		//TODO do nothing
	}

	//Msg Check.
	pl := PricelistByEpoch(vm.blockHeight)

	msgGas := pl.OnChainMessage(cmsg.ChainLength())
	msgGasCost := msgGas.Total()
	// this should never happen, but is currently still exercised by some tests
	if msgGasCost > msg.GasLimit {
		gasOutputs := ZeroGasOutputs()
		gasOutputs.MinerPenalty = types.BigMul(vm.baseFee, abi.NewTokenAmount(msgGasCost))
		return &ApplyRet{
			MessageReceipt: types.MessageReceipt{
				ExitCode: exitcode.SysErrOutOfGas,
				GasUsed:  0,
			},
			GasCosts: &gasOutputs,
			Duration: time.Since(start),
			ActorErr: aerrors.Newf(exitcode.SysErrOutOfGas,
				"message gas limit does not cover on-chain gas costs"),
		}, nil
	}

	st := vm.cstate

	minerPenaltyAmount := types.BigMul(vm.baseFee, abi.NewTokenAmount(msg.GasLimit))
	fromActor, err := st.GetActor(msg.From)
	// this should never happen, but is currently still exercised by some tests
	if err != nil {
		if xerrors.Is(err, types.ErrActorNotFound) {
			gasOutputs := ZeroGasOutputs()
			gasOutputs.MinerPenalty = minerPenaltyAmount
			return &ApplyRet{
				MessageReceipt: types.MessageReceipt{
					ExitCode: exitcode.SysErrSenderInvalid,
					GasUsed:  0,
				},
				ActorErr: aerrors.Newf(exitcode.SysErrSenderInvalid, "actor not found: %s", msg.From),
				GasCosts: &gasOutputs,
				Duration: time.Since(start),
			}, nil
		}
		return nil, xerrors.Errorf("failed to look up from actor: %w", err)
	}

	// this should never happen, but is currently still exercised by some tests
	if !builtin.IsAccountActor(fromActor.Code) {
		gasOutputs := ZeroGasOutputs()
		gasOutputs.MinerPenalty = minerPenaltyAmount
		return &ApplyRet{
			MessageReceipt: types.MessageReceipt{
				ExitCode: exitcode.SysErrSenderInvalid,
				GasUsed:  0,
			},
			ActorErr: aerrors.Newf(exitcode.SysErrSenderInvalid, "send from not account actor: %s", fromActor.Code),
			GasCosts: &gasOutputs,
			Duration: time.Since(start),
		}, nil
	}

	if msg.Nonce != fromActor.Nonce {
		gasOutputs := ZeroGasOutputs()
		gasOutputs.MinerPenalty = minerPenaltyAmount
		return &ApplyRet{
			MessageReceipt: types.MessageReceipt{
				ExitCode: exitcode.SysErrSenderStateInvalid,
				GasUsed:  0,
			},
			ActorErr: aerrors.Newf(exitcode.SysErrSenderStateInvalid,
				"actor nonce invalid: msg:%d != state:%d", msg.Nonce, fromActor.Nonce),

			GasCosts: &gasOutputs,
			Duration: time.Since(start),
		}, nil
	}

	gascost := types.BigMul(types.NewInt(uint64(msg.GasLimit)), msg.GasFeeCap)
	if fromActor.Balance.LessThan(gascost) {
		gasOutputs := ZeroGasOutputs()
		gasOutputs.MinerPenalty = minerPenaltyAmount
		return &ApplyRet{
			MessageReceipt: types.MessageReceipt{
				ExitCode: exitcode.SysErrSenderStateInvalid,
				GasUsed:  0,
			},
			ActorErr: aerrors.Newf(exitcode.SysErrSenderStateInvalid,
				"actor balance less than needed: %s < %s", types.FIL(fromActor.Balance), types.FIL(gascost)),
			GasCosts: &gasOutputs,
			Duration: time.Since(start),
		}, nil
	}

	gasHolder := &types.Actor{Balance: types.NewInt(0)}
	if err := vm.transferToGasHolder(msg.From, gasHolder, gascost); err != nil {
		return nil, xerrors.Errorf("failed to withdraw gas funds: %w", err)
	}

	if err := vm.incrementNonce(msg.From); err != nil {
		return nil, err
	}

	if err := st.Snapshot(ctx); err != nil {
		return nil, xerrors.Errorf("snapshot failed: %w", err)
	}
	defer st.ClearSnapshot()


	//Msg execute.
	var gasTotalUsed int64 = 0
	var gasTotalOutput = new(GasOutputs)
	var ErrCode exitcode.ExitCode
	var runT = new(Runtime)
	var ActorError aerrors.ActorError
	for _, v := range cmsg.Receives {
		/// new types.Msg
		newMsg := &types.Message{
			Version: cmsg.Version,
			To: v.To,
			From:cmsg.From,
			Nonce: cmsg.Nonce,
			Value: v.Value,
			GasLimit: cmsg.GasLimit,
			GasFeeCap: cmsg.GasFeeCap,
			GasPremium: cmsg.GasPremium,
			Method: v.Method,
			Params: v.Params,
		}

		ret, actorErr, rt := vm.send(ctx, newMsg, runT, &msgGas, start)
		if aerrors.IsFatal(actorErr) {
			return nil, xerrors.Errorf("[from=%s,to=%s,n=%d,m=%d,h=%d] fatal error: %w", newMsg.From, newMsg.To, newMsg.Nonce, newMsg.Method, vm.blockHeight, actorErr)
		}

		if actorErr != nil {
			log.Warnw("Send actor error", "from", newMsg.From, "to", newMsg.To, "nonce", newMsg.Nonce, "method", newMsg.Method, "height", vm.blockHeight, "error", fmt.Sprintf("%+v", actorErr))
		}

		if actorErr != nil && len(ret) != 0 {
			// This should not happen, something is wonky
			return nil, xerrors.Errorf("message invocation errored, but had a return value anyway: %w", actorErr)
		}

		if rt == nil {
			return nil, xerrors.Errorf("send returned nil runtime, send error was: %s", actorErr)
		}

		if len(ret) != 0 {
			// safely override actorErr since it must be nil
			actorErr = rt.chargeGasSafe(rt.Pricelist().OnChainReturnValue(len(ret)))
			if actorErr != nil {
				ret = nil
			}
		}

		var errcode exitcode.ExitCode
		var gasUsed int64

		if errcode = aerrors.RetCode(actorErr); errcode != 0 {
			// revert all state changes since snapshot
			if err := st.Revert(); err != nil {
				return nil, xerrors.Errorf("revert state failed: %w", err)
			}
		}

		rt.finilizeGasTracing()

		gasUsed = rt.gasUsed
		if gasUsed < 0 {
			gasUsed = 0
		}

		burn, err := vm.ShouldBurn(ctx, st, newMsg, errcode)
		if err != nil {
			return nil, xerrors.Errorf("deciding whether should burn failed: %w", err)
		}
		gasTotalUsed += gasUsed
		gasOutputs := ComputeGasOutputs(gasUsed, msg.GasLimit, vm.baseFee, msg.GasFeeCap, msg.GasPremium, burn)
		gasTotalOutput.Add(gasOutputs)
		if errcode != 0 {
			ErrCode = errcode
			ActorError = actorErr
			break
		}
		runT = rt
	}

	//ret, actorErr, rt := vm.send(ctx, msg, nil, &msgGas, start)
	//if aerrors.IsFatal(actorErr) {
	//	return nil, xerrors.Errorf("[from=%s,to=%s,n=%d,m=%d,h=%d] fatal error: %w", msg.From, msg.To, msg.Nonce, msg.Method, vm.blockHeight, actorErr)
	//}
	//
	//if actorErr != nil {
	//	log.Warnw("Send actor error", "from", msg.From, "to", msg.To, "nonce", msg.Nonce, "method", msg.Method, "height", vm.blockHeight, "error", fmt.Sprintf("%+v", actorErr))
	//}
	//
	//if actorErr != nil && len(ret) != 0 {
	//	// This should not happen, something is wonky
	//	return nil, xerrors.Errorf("message invocation errored, but had a return value anyway: %w", actorErr)
	//}
	//
	//if rt == nil {
	//	return nil, xerrors.Errorf("send returned nil runtime, send error was: %s", actorErr)
	//}
	//
	//if len(ret) != 0 {
	//	// safely override actorErr since it must be nil
	//	actorErr = rt.chargeGasSafe(rt.Pricelist().OnChainReturnValue(len(ret)))
	//	if actorErr != nil {
	//		ret = nil
	//	}
	//}
	//
	//var errcode exitcode.ExitCode
	//var gasUsed int64
	//
	//if errcode = aerrors.RetCode(actorErr); errcode != 0 {
	//	// revert all state changes since snapshot
	//	if err := st.Revert(); err != nil {
	//		return nil, xerrors.Errorf("revert state failed: %w", err)
	//	}
	//}
	//
	//rt.finilizeGasTracing()
	//
	//gasUsed = rt.gasUsed
	//if gasUsed < 0 {
	//	gasUsed = 0
	//}
	//
	//burn, err := vm.ShouldBurn(ctx, st, msg, errcode)
	//if err != nil {
	//	return nil, xerrors.Errorf("deciding whether should burn failed: %w", err)
	//}

	//execute end.
	//gasOutputs := ComputeGasOutputs(gasTotalUsed, msg.GasLimit, vm.baseFee, msg.GasFeeCap, msg.GasPremium, burn)

	if err := vm.transferFromGasHolder(builtin.BurntFundsActorAddr, gasHolder,
		gasTotalOutput.BaseFeeBurn); err != nil {
		return nil, xerrors.Errorf("failed to burn base fee: %w", err)
	}

	if err := vm.transferFromGasHolder(reward.Address, gasHolder, gasTotalOutput.MinerTip); err != nil {
		return nil, xerrors.Errorf("failed to give miner gas reward: %w", err)
	}

	if err := vm.transferFromGasHolder(builtin.BurntFundsActorAddr, gasHolder,
		gasTotalOutput.OverEstimationBurn); err != nil {
		return nil, xerrors.Errorf("failed to burn overestimation fee: %w", err)
	}

	// refund unused gas
	if err := vm.transferFromGasHolder(msg.From, gasHolder, gasTotalOutput.Refund); err != nil {
		return nil, xerrors.Errorf("failed to refund gas: %w", err)
	}

	if types.BigCmp(types.NewInt(0), gasHolder.Balance) != 0 {
		return nil, xerrors.Errorf("gas handling math is wrong")
	}

	return &ApplyRet{
		MessageReceipt: types.MessageReceipt{
			ExitCode: ErrCode,
			Return:   nil, //TODO ret.
			GasUsed:  gasTotalUsed,
		},
		ActorErr:       ActorError,
		ExecutionTrace: runT.executionTrace,
		GasCosts:       gasTotalOutput,
		Duration:       time.Since(start),
	}, nil

	//return &ApplyRet{
	//	MessageReceipt: types.MessageReceipt{
	//		ExitCode: errcode,
	//		Return:   ret,
	//		GasUsed:  gasUsed,
	//	},
	//	ActorErr:       actorErr,
	//	ExecutionTrace: rt.executionTrace,
	//	GasCosts:       &gasOutputs,
	//	Duration:       time.Since(start),
	//}, nil
}