package openssl

import (
	"encoding/hex"
	"testing"
)

func TestHashStreebog256_RFC6986_M1(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	msg := []byte("012345678901234567890123456789012345678901234567890123456789012")
	expected := "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"

	digest, err := HashBytes(NID_Streebog256, msg)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	got := hex.EncodeToString(digest)
	if got != expected {
		t.Errorf("Streebog-256(M1):\ngot  %s\nwant %s", got, expected)
	}
}

func TestHashStreebog512_RFC6986_M1(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	msg := []byte("012345678901234567890123456789012345678901234567890123456789012")
	expected := "1b54d01a4af5b9d5cc3d86d68d285462" +
		"b19abc2475222f35c085122be4ba1ffa" +
		"00ad30f8767b3a82384c6574f024c311" +
		"e2a481332b08ef7f41797891c1646f48"

	digest, err := HashBytes(NID_Streebog512, msg)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	got := hex.EncodeToString(digest)
	if got != expected {
		t.Errorf("Streebog-512(M1):\ngot  %s\nwant %s", got, expected)
	}
}

func TestMDCtx_IncrementalHash(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost-engine not available: %v", err)
	}

	// Hash in two parts should equal hash of full message
	full := []byte("012345678901234567890123456789012345678901234567890123456789012")
	part1 := full[:30]
	part2 := full[30:]

	ctx, err := NewMDCtx(NID_Streebog256)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	ctx.Update(part1)
	ctx.Update(part2)
	incremental, err := ctx.Final()
	if err != nil {
		t.Fatal(err)
	}

	oneShot, err := HashBytes(NID_Streebog256, full)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(incremental) != hex.EncodeToString(oneShot) {
		t.Error("incremental hash != one-shot hash")
	}
}
