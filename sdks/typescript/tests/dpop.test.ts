import { describe, it, expect } from "vitest";
import * as jose from "jose";
import { DPoPClient, computeJkt, verifyDPoPProof } from "../src/dpop.js";
import { DPoPError } from "../src/errors.js";

describe("DPoPClient", () => {
  it("generates ephemeral key pair on create", async () => {
    const client = await DPoPClient.create();
    expect(client.jkt).toBeTruthy();
    expect(typeof client.jkt).toBe("string");
  });

  it("creates valid DPoP proof JWT", async () => {
    const client = await DPoPClient.create();
    const proof = await client.createProof("POST", "https://api.example.com/data");

    // Decode and verify structure
    const header = jose.decodeProtectedHeader(proof);
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk).toBeDefined();
    expect(header.jwk?.kty).toBe("EC");
    expect(header.jwk?.crv).toBe("P-256");

    const payload = jose.decodeJwt(proof);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://api.example.com/data");
    expect(payload.jti).toBeTruthy();
    expect(payload.iat).toBeDefined();
  });

  it("includes ath when access_token provided", async () => {
    const client = await DPoPClient.create();
    const proof = await client.createProof(
      "GET",
      "https://api.example.com",
      "my_access_token",
    );

    const payload = jose.decodeJwt(proof);
    expect(payload.ath).toBeTruthy();
    expect(typeof payload.ath).toBe("string");
  });

  it("includes nonce when provided", async () => {
    const client = await DPoPClient.create();
    const proof = await client.createProof(
      "GET",
      "https://api.example.com",
      undefined,
      "server-nonce-123",
    );

    const payload = jose.decodeJwt(proof);
    expect(payload.nonce).toBe("server-nonce-123");
  });

  it("creates correct proof headers", async () => {
    const client = await DPoPClient.create();
    const headers = await client.createProofHeaders(
      "my_token",
      "POST",
      "https://api.example.com/data",
    );

    expect(headers.Authorization).toBe("DPoP my_token");
    expect(headers.DPoP).toBeTruthy();

    // Verify the DPoP proof is a valid JWT
    const header = jose.decodeProtectedHeader(headers.DPoP);
    expect(header.typ).toBe("dpop+jwt");
  });

  it("jkt is consistent across calls", async () => {
    const client = await DPoPClient.create();
    expect(client.jkt).toBe(client.jkt);
  });

  it("different clients have different jkts", async () => {
    const client1 = await DPoPClient.create();
    const client2 = await DPoPClient.create();
    expect(client1.jkt).not.toBe(client2.jkt);
  });
});

describe("computeJkt", () => {
  it("computes deterministic thumbprint for same key", async () => {
    const jwk: jose.JWK = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    };
    const jkt1 = await computeJkt(jwk);
    const jkt2 = await computeJkt(jwk);
    expect(jkt1).toBe(jkt2);
    expect(typeof jkt1).toBe("string");
    expect(jkt1.length).toBeGreaterThan(0);
  });
});

describe("verifyDPoPProof", () => {
  it("rejects when token has no cnf.jkt", async () => {
    await expect(
      verifyDPoPProof({
        tokenClaims: { sub: "test" },
        dpopProof: "dummy",
        httpMethod: "GET",
        httpUri: "https://example.com",
      }),
    ).rejects.toThrow(DPoPError);
    await expect(
      verifyDPoPProof({
        tokenClaims: { sub: "test" },
        dpopProof: "dummy",
        httpMethod: "GET",
        httpUri: "https://example.com",
      }),
    ).rejects.toThrow("cnf.jkt");
  });

  it("rejects invalid JWT string", async () => {
    await expect(
      verifyDPoPProof({
        tokenClaims: { cnf: { jkt: "some-jkt" } },
        dpopProof: "not-a-jwt",
        httpMethod: "GET",
        httpUri: "https://example.com",
      }),
    ).rejects.toThrow(DPoPError);
  });

  it("verifies valid proof from DPoPClient", async () => {
    const client = await DPoPClient.create();
    const method = "POST";
    const uri = "https://api.example.com/data";
    const accessToken = "test_access_token";

    const proof = await client.createProof(method, uri, accessToken);
    const claims = { cnf: { jkt: client.jkt } };

    const result = await verifyDPoPProof({
      tokenClaims: claims,
      dpopProof: proof,
      httpMethod: method,
      httpUri: uri,
    });

    expect(result.jkt).toBe(client.jkt);
    expect(result.htm).toBe("POST");
    expect(result.htu).toBe(uri);
  });

  it("rejects proof with wrong HTTP method", async () => {
    const client = await DPoPClient.create();
    const proof = await client.createProof("GET", "https://example.com");

    await expect(
      verifyDPoPProof({
        tokenClaims: { cnf: { jkt: client.jkt } },
        dpopProof: proof,
        httpMethod: "POST",
        httpUri: "https://example.com",
      }),
    ).rejects.toThrow("htm mismatch");
  });

  it("rejects proof with wrong URI", async () => {
    const client = await DPoPClient.create();
    const proof = await client.createProof("GET", "https://example.com/a");

    await expect(
      verifyDPoPProof({
        tokenClaims: { cnf: { jkt: client.jkt } },
        dpopProof: proof,
        httpMethod: "GET",
        httpUri: "https://example.com/b",
      }),
    ).rejects.toThrow("htu mismatch");
  });

  it("rejects proof with wrong key binding", async () => {
    const client1 = await DPoPClient.create();
    const client2 = await DPoPClient.create();
    const proof = await client1.createProof("GET", "https://example.com");

    // Token bound to client2's key but proof from client1
    await expect(
      verifyDPoPProof({
        tokenClaims: { cnf: { jkt: client2.jkt } },
        dpopProof: proof,
        httpMethod: "GET",
        httpUri: "https://example.com",
      }),
    ).rejects.toThrow("thumbprint does not match");
  });
});
