using SecureVault.Core;

namespace SecureVault.Tests;

/// <summary>Known-answer tests against published vectors, so our wiring matches the reference implementations.</summary>
public class CryptoVectorTests
{
    private static byte[] Hex(string h) => Convert.FromHexString(h);

    [Fact] // draft-irtf-cfrg-xchacha-03, Appendix A.3.1
    public void XChaCha20Poly1305_MatchesDraftVector()
    {
        var pt = Hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        var aad = Hex("50515253c0c1c2c3c4c5c6c7");
        var key = Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var nonce = Hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        var ct = Hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e");
        var tag = Hex("c0875924c1c7987947deafd8780acf49");

        var sealedBytes = VaultCrypto.Seal(key, nonce, aad, pt);
        Assert.Equal([.. ct, .. tag], sealedBytes);

        var opened = new byte[pt.Length];
        Assert.True(VaultCrypto.TryOpen(key, nonce, aad, sealedBytes, opened));
        Assert.Equal(pt, opened);
    }

    [Fact] // libsodium test/default/pwhash_argon2id.c tv[0] → .exp line 1
    public void Argon2id_MatchesLibsodiumVector()
    {
        var pwd = Hex("a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6");
        var salt = Hex("5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2")[..16];
        var expected = Hex("18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e7348249d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1");
        Assert.Equal(155, expected.Length);

        // memlimit 7256678 bytes → libsodium uses memlimit / 1024 = 7086 KiB. ops 5, 1 lane.
        var output = new byte[155];
        VaultCrypto.DerivePasswordKey(pwd, salt, new KdfParams(7256678 / 1024, 5), output);
        Assert.Equal(expected, output);
    }

    [Fact]
    public void Aead_RejectsWrongKey_AndTamper()
    {
        var key = VaultCrypto.RandomBytes(32);
        var nonce = VaultCrypto.RandomBytes(24);
        var ct = VaultCrypto.Seal(key, nonce, "ad"u8, "hello"u8);
        var buf = new byte[5];
        Assert.False(VaultCrypto.TryOpen(VaultCrypto.RandomBytes(32), nonce, "ad"u8, ct, buf));
        Assert.False(VaultCrypto.TryOpen(key, nonce, "AD"u8, ct, buf));
        ct[0] ^= 1;
        Assert.False(VaultCrypto.TryOpen(key, nonce, "ad"u8, ct, buf));
    }

    [Fact]
    public void Commitment_DetectsWrongKey()
    {
        var k = VaultCrypto.RandomBytes(32);
        var c = VaultCrypto.Commit(k, "ctx");
        Assert.True(VaultCrypto.VerifyCommit(k, "ctx", c));
        Assert.False(VaultCrypto.VerifyCommit(VaultCrypto.RandomBytes(32), "ctx", c));
        Assert.False(VaultCrypto.VerifyCommit(k, "other", c));
    }
}
