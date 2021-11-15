package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/go-state-types/network"
	"github.com/filecoin-project/lotus/build"
	block "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
	"io"
)



type Receive struct {
	To   address.Address
	Value abi.TokenAmount
	Method abi.MethodNum
	Params []byte
}

type MultiMsg struct {
	Version uint64

	//To   address.Address
	From address.Address

	Nonce uint64

	//Value abi.TokenAmount

	GasLimit   int64
	GasFeeCap  abi.TokenAmount
	GasPremium abi.TokenAmount

	//Method abi.MethodNum
	//Params []byte
	Receives  []Receive
}


func (m *MultiMsg) Caller() address.Address {
	return m.From
}

func (m *MultiMsg) Receiver() address.Address {
	return m.Receives[0].To
}

func (m *MultiMsg) ValueReceived() abi.TokenAmount {
	return m.Receives[0].Value
}

//func DecodeMessage(b []byte) (*MultiMsg, error) {
//	var msg Message
//	if err := msg.UnmarshalCBOR(bytes.NewReader(b)); err != nil {
//		return nil, err
//	}
//
//	if msg.Version != MessageVersion {
//		return nil, fmt.Errorf("decoded message had incorrect version (%d)", msg.Version)
//	}
//
//	return &msg, nil
//}

func (m *MultiMsg) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := m.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *MultiMsg) ChainLength() int {
	ser, err := m.Serialize()
	if err != nil {
		panic(err)
	}
	return len(ser)
}

func (m *MultiMsg) ToStorageBlock() (block.Block, error) {
	data, err := m.Serialize()
	if err != nil {
		return nil, err
	}

	c, err := abi.CidBuilder.Sum(data)
	if err != nil {
		return nil, err
	}

	return block.NewBlockWithCid(data, c)
}

func (m *MultiMsg) Cid() cid.Cid {
	b, err := m.ToStorageBlock()
	if err != nil {
		panic(fmt.Sprintf("failed to marshal message: %s", err)) // I think this is maybe sketchy, what happens if we try to serialize a message with an undefined address in it?
	}

	return b.Cid()
}

func (t *MultiMsg) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	if _, err := w.Write(lengthBufMessage); err != nil {
		return err
	}

	scratch := make([]byte, 9)

	// t.Version (uint64) (uint64)

	if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(t.Version)); err != nil {
		return err
	}

	// t.To (address.Address) (struct)
	//if err := t.To.MarshalCBOR(w); err != nil {
	//	return err
	//}

	// t.From (address.Address) (struct)
	if err := t.From.MarshalCBOR(w); err != nil {
		return err
	}

	// t.Nonce (uint64) (uint64)

	if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(t.Nonce)); err != nil {
		return err
	}

	// t.Value (big.Int) (struct)
	//if err := t.Value.MarshalCBOR(w); err != nil {
	//	return err
	//}

	// t.GasLimit (int64) (int64)
	if t.GasLimit >= 0 {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(t.GasLimit)); err != nil {
			return err
		}
	} else {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajNegativeInt, uint64(-t.GasLimit-1)); err != nil {
			return err
		}
	}

	// t.GasFeeCap (big.Int) (struct)
	if err := t.GasFeeCap.MarshalCBOR(w); err != nil {
		return err
	}

	// t.GasPremium (big.Int) (struct)
	if err := t.GasPremium.MarshalCBOR(w); err != nil {
		return err
	}

	// t.Method (abi.MethodNum) (uint64)

	//if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(t.Method)); err != nil {
	//	return err
	//}

	// t.Params ([]uint8) (slice)
	//if len(t.Params) > cbg.ByteArrayMaxLen {
	//	return xerrors.Errorf("Byte array in field t.Params was too long")
	//}

	//if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajByteString, uint64(len(t.Params))); err != nil {
	//	return err
	//}

	//if _, err := w.Write(t.Params[:]); err != nil {
	//	return err
	//}
	re, err := json.Marshal(t.Receives)
	if err != nil {
		return err
	}
	if _, err = w.Write(re[:]); err != nil {
		return err
	}

	return nil
}

func (t *MultiMsg) UnmarshalCBOR(r io.Reader) error {
	*t = MultiMsg{}

	br := cbg.GetPeeker(r)
	scratch := make([]byte, 8)

	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
	if err != nil {
		return err
	}
	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 10 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Version (uint64) (uint64)

	{

		maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		t.Version = uint64(extra)

	}
	// t.To (address.Address) (struct)

	//{
	//
	//	if err := t.To.UnmarshalCBOR(br); err != nil {
	//		return xerrors.Errorf("unmarshaling t.To: %w", err)
	//	}
	//
	//}
	// t.From (address.Address) (struct)

	{

		if err := t.From.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.From: %w", err)
		}

	}
	// t.Nonce (uint64) (uint64)

	{

		maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		t.Nonce = uint64(extra)

	}
	// t.Value (big.Int) (struct)

	//{
	//
	//	if err := t.Value.UnmarshalCBOR(br); err != nil {
	//		return xerrors.Errorf("unmarshaling t.Value: %w", err)
	//	}
	//
	//}
	// t.GasLimit (int64) (int64)
	{
		maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
		var extraI int64
		if err != nil {
			return err
		}
		switch maj {
		case cbg.MajUnsignedInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 positive overflow")
			}
		case cbg.MajNegativeInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 negative oveflow")
			}
			extraI = -1 - extraI
		default:
			return fmt.Errorf("wrong type for int64 field: %d", maj)
		}

		t.GasLimit = int64(extraI)
	}
	// t.GasFeeCap (big.Int) (struct)

	{

		if err := t.GasFeeCap.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.GasFeeCap: %w", err)
		}

	}
	// t.GasPremium (big.Int) (struct)

	{

		if err := t.GasPremium.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.GasPremium: %w", err)
		}

	}
	// t.Method (abi.MethodNum) (uint64)

	//{
	//
	//	maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
	//	if err != nil {
	//		return err
	//	}
	//	if maj != cbg.MajUnsignedInt {
	//		return fmt.Errorf("wrong type for uint64 field")
	//	}
	//	t.Method = abi.MethodNum(extra)
	//
	//}
	// t.Params ([]uint8) (slice)

	//maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
	//if err != nil {
	//	return err
	//}

	//if extra > cbg.ByteArrayMaxLen {
	//	return fmt.Errorf("t.Params: byte array too large (%d)", extra)
	//}
	//if maj != cbg.MajByteString {
	//	return fmt.Errorf("expected byte array")
	//}

	//if extra > 0 {
	//	t.Params = make([]uint8, extra)
	//}
	//
	//if _, err := io.ReadFull(br, t.Params[:]); err != nil {
	//	return err
	//}

	re, err := io.ReadAll(br)
	if err != nil {
		return err
	}
	var Res []Receive
	if err = json.Unmarshal(re, &Res); err != nil {
		return err
	}
	t.Receives = Res

	return nil
}

type mMultiCid struct {
	*RawMultiMessage
	CID cid.Cid
}

type RawMultiMessage MultiMsg

func (m *MultiMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(&mMultiCid{
		RawMultiMessage: (*RawMultiMessage)(m),
		CID:        m.Cid(),
	})
}

func (m *MultiMsg) RequiredFunds() BigInt {
	return BigMul(m.GasFeeCap, NewInt(uint64(m.GasLimit)))
}

func (m *MultiMsg) VMMessage() *Message {
	return &Message{
		GasPremium:m.GasPremium,
		Version: m.Version,
		Nonce: m.Nonce,
		GasLimit: m.GasLimit,
		GasFeeCap: m.GasFeeCap,
	}
}

func (m *MultiMsg) Equals(o *Message) bool {
	return m.Cid() == o.Cid()
}

func (m *MultiMsg) EqualCall(o *Message) bool {
	m1 := *m
	m2 := *o

	m1.GasLimit, m2.GasLimit = 0, 0
	m1.GasFeeCap, m2.GasFeeCap = big.Zero(), big.Zero()
	m1.GasPremium, m2.GasPremium = big.Zero(), big.Zero()

	return (&m1).Equals(&m2)
}

func (m *MultiMsg) ValidForBlockInclusion(minGas int64, version network.Version) error {
	if m.Version != 0 {
		return xerrors.New("'Version' unsupported")
	}

	//if m.To == address.Undef {
	//	return xerrors.New("'To' address cannot be empty")
	//}
	//
	//if m.To == build.ZeroAddress && version >= network.Version7 {
	//	return xerrors.New("invalid 'To' address")
	//}

	if m.From == address.Undef {
		return xerrors.New("'From' address cannot be empty")
	}

	//if m.Value.Int == nil {
	//	return xerrors.New("'Value' cannot be nil")
	//}
	//
	//if m.Value.LessThan(big.Zero()) {
	//	return xerrors.New("'Value' field cannot be negative")
	//}
	//
	//if m.Value.GreaterThan(TotalFilecoinInt) {
	//	return xerrors.New("'Value' field cannot be greater than total filecoin supply")
	//}

	if m.GasFeeCap.Int == nil {
		return xerrors.New("'GasFeeCap' cannot be nil")
	}

	if m.GasFeeCap.LessThan(big.Zero()) {
		return xerrors.New("'GasFeeCap' field cannot be negative")
	}

	if m.GasPremium.Int == nil {
		return xerrors.New("'GasPremium' cannot be nil")
	}

	if m.GasPremium.LessThan(big.Zero()) {
		return xerrors.New("'GasPremium' field cannot be negative")
	}

	if m.GasPremium.GreaterThan(m.GasFeeCap) {
		return xerrors.New("'GasFeeCap' less than 'GasPremium'")
	}

	if m.GasLimit > build.BlockGasLimit {
		return xerrors.New("'GasLimit' field cannot be greater than a block's gas limit")
	}

	// since prices might vary with time, this is technically semantic validation
	if m.GasLimit < minGas {
		return xerrors.Errorf("'GasLimit' field cannot be less than the cost of storing a message on chain %d < %d", m.GasLimit, minGas)
	}

	return nil
}

//const TestGasLimit = 100e6



//func (m *MultiMsg) ToStorageBlock() (block.Block, error) {
//	data, err := m.Serialize()
//	if err != nil {
//		return nil, err
//	}
//
//	c, err := abi.CidBuilder.Sum(data)
//	if err != nil {
//		return nil, err
//	}
//
//	return block.NewBlockWithCid(data, c)
//}

type SignedMultiMsg struct {
	Message   MultiMsg
	Signature crypto.Signature
}

func (sm *SignedMultiMsg) ToStorageBlock() (block.Block, error) {
	if sm.Signature.Type == crypto.SigTypeBLS {
		return sm.Message.ToStorageBlock()
	}

	data, err := sm.Serialize()
	if err != nil {
		return nil, err
	}

	c, err := abi.CidBuilder.Sum(data)
	if err != nil {
		return nil, err
	}

	return block.NewBlockWithCid(data, c)
}

func (sm *SignedMultiMsg) Cid() cid.Cid {
	if sm.Signature.Type == crypto.SigTypeBLS {
		return sm.Message.Cid()
	}

	sb, err := sm.ToStorageBlock()
	if err != nil {
		panic(err)
	}

	return sb.Cid()
}



//type SignedMessage struct {
//	Message   Message
//	Signature crypto.Signature
//}

func DecodeSignedMultiMessage(data []byte) (*SignedMultiMsg, error) {
	var msg SignedMultiMsg
	if err := msg.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
		return nil, err
	}

	return &msg, nil
}

func (sm *SignedMultiMsg) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := sm.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type smMultiCid struct {
	*RawSignedMultiMessage
	CID cid.Cid
}

type RawSignedMultiMessage SignedMultiMsg

func (sm *SignedMultiMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(&smMultiCid{
		RawSignedMultiMessage: (*RawSignedMultiMessage)(sm),
		CID:              sm.Cid(),
	})
}

func (sm *SignedMultiMsg) ChainLength() int {
	var ser []byte
	var err error
	if sm.Signature.Type == crypto.SigTypeBLS {
		// BLS chain message length doesn't include signature
		ser, err = sm.Message.Serialize()
	} else {
		ser, err = sm.Serialize()
	}
	if err != nil {
		panic(err)
	}
	return len(ser)
}

func (sm *SignedMultiMsg) Size() int {
	serdata, err := sm.Serialize()
	if err != nil {
		log.Errorf("serializing message failed: %s", err)
		return 0
	}

	return len(serdata)
}

func (sm *SignedMultiMsg) VMMessage() *Message {
	return sm.Message.VMMessage()
}


func (t *SignedMultiMsg) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	if _, err := w.Write(lengthBufSignedMessage); err != nil {
		return err
	}

	// t.Message (types.Message) (struct)
	if err := t.Message.MarshalCBOR(w); err != nil {
		return err
	}

	// t.Signature (crypto.Signature) (struct)
	if err := t.Signature.MarshalCBOR(w); err != nil {
		return err
	}
	return nil
}

func (t *SignedMultiMsg) UnmarshalCBOR(r io.Reader) error {
	*t = SignedMultiMsg{}

	br := cbg.GetPeeker(r)
	scratch := make([]byte, 8)

	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
	if err != nil {
		return err
	}
	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Message (types.Message) (struct)

	{

		if err := t.Message.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.Message: %w", err)
		}

	}
	// t.Signature (crypto.Signature) (struct)

	{

		if err := t.Signature.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.Signature: %w", err)
		}

	}
	return nil
}