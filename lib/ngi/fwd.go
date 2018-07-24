/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"errors"
	"math/rand"
	"time"

	"../tlv"
)

var (
	ErrTimeout        = errors.New("timeout")
	ErrResponseStatus = errors.New("bad command response status")
)

type Command struct {
	Local          string                  `tlv:"8"`
	FWD            string                  `tlv:"8"`
	Module         string                  `tlv:"8"`
	Command        string                  `tlv:"8"`
	Parameters     parametersComponent     `tlv:"8"`
	Timestamp      uint64                  `tlv:"8"`
	Nonce          uint64                  `tlv:"8"`
	SignatureInfo  signatureInfoComponent  `tlv:"8"`
	SignatureValue signatureValueComponent `tlv:"8*"`
}

func (cmd *Command) WriteTo(w tlv.Writer) error {
	return w.Write(cmd, 7)
}

func (cmd *Command) ReadFrom(r tlv.Reader) error {
	return r.Read(cmd, 7)
}

type parametersComponent struct {
	Parameters Parameters `tlv:"104"`
}

type signatureInfoComponent struct {
	SignatureInfo SignatureInfo `tlv:"22"`
}

type signatureValueComponent struct {
	SignatureValue []byte `tlv:"23"`
}

type Parameters struct {
	Name             Name     `tlv:"7?"`
	FaceID           uint64   `tlv:"105?"`
	URI              string   `tlv:"114?"`
	Origin           uint64   `tlv:"111?"`
	Cost             uint64   `tlv:"106?"`
	Flags            uint64   `tlv:"108?"`
	Mask             uint64   `tlv:"112?"`
	Strategy         Strategy `tlv:"107?"`
	ExpirationPeriod uint64   `tlv:"109?"`
	FacePersistency  uint64   `tlv:"133?"`
}

type Strategy struct {
	Name Name `tlv:"7"`
}

type CommandResponse struct {
	StatusCode uint64     `tlv:"102"`
	StatusText string     `tlv:"103"`
	Parameters Parameters `tlv:"104?"`
}

type ForwarderStatus struct {
	FWDVersion       string `tlv:"128"`
	StartTimestamp   uint64 `tlv:"129"`
	CurrentTimestamp uint64 `tlv:"130"`
	NameTreeEntry    uint64 `tlv:"131"`
	FIBEntry         uint64 `tlv:"132"`
	PITEntry         uint64 `tlv:"133"`
	MeasurementEntry uint64 `tlv:"134"`
	CSEntry          uint64 `tlv:"135"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	InNack           uint64 `tlv:"151"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
	OutNack          uint64 `tlv:"152"`
}

type FaceStatus struct {
	FaceID           uint64 `tlv:"105"`
	URI              string `tlv:"114"`
	LocalURI         string `tlv:"129"`
	ExpirationPeriod uint64 `tlv:"109?"`
	Scope            uint64 `tlv:"132"`
	Persistency      uint64 `tlv:"133"`
	LinkType         uint64 `tlv:"134"`
	Flags            uint64 `tlv:"108"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	InNack           uint64 `tlv:"151"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
	OutNack          uint64 `tlv:"152"`
	InByte           uint64 `tlv:"148"`
	OutByte          uint64 `tlv:"149"`
}

type FIBEntry struct {
	Name    Name            `tlv:"7"`
	NextHop []NextHopRecord `tlv:"129"`
}

type NextHopRecord struct {
	FaceID uint64 `tlv:"105"`
	Cost   uint64 `tlv:"106"`
}

type RIBEntry struct {
	Name  Name    `tlv:"7"`
	Route []Route `tlv:"129"`
}

type Route struct {
	FaceID           uint64 `tlv:"105"`
	Origin           uint64 `tlv:"111"`
	Cost             uint64 `tlv:"106"`
	Flags            uint64 `tlv:"108"`
	ExpirationPeriod uint64 `tlv:"109?"`
}

type StrategyChoice struct {
	Name     Name     `tlv:"7"`
	Strategy Strategy `tlv:"107"`
}

func SendControl(w Sender, module, command string, params *Parameters, key Key) error {
	cmd := &Command{
		Local:     "localhost",
		FWD:       "fwd",
		Module:    module,
		Command:   command,
		Timestamp: uint64(time.Now().UnixNano() / 1000000),
		Nonce:     uint64(rand.Uint32()),
	}
	var err error
	cmd.Parameters.Parameters = *params
	cmd.SignatureInfo.SignatureInfo.SignatureType = key.SignatureType()
	cmd.SignatureInfo.SignatureInfo.KeyLocator.Name = key.Locator()
	cmd.SignatureValue.SignatureValue, err = key.Sign(cmd)
	if err != nil {
		return err
	}

	i := new(Interest)
	err = tlv.Copy(&i.Name, cmd)
	if err != nil {
		return err
	}
	d, err := w.SendInterest(i)
	if err != nil {
		return err
	}
	var resp CommandResponse
	err = tlv.Unmarshal(d.Content, &resp, 101)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return ErrResponseStatus
	}
	return nil
}
