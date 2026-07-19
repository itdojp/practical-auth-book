```javascript
const credential = await navigator.credentials.create({
    publicKey: { attestation: "none" }
});
```

### Attestation の選択: 一般向け Passkey と管理対象 enterprise

WebAuthn の `attestation` の既定値も `none` である。

- **プライバシー**: AAGUID など認証器の型式に関係する情報が含まれ得るため最小化する。
- **互換性**: 一般向け登録を `direct` の検証に依存させない。
- **運用**: 信頼アンカー、証明書失効、メタデータ更新、拒否時の利用者支援を設計する。`direct` はそれだけで管理対象端末であることを証明しない。

一般向け登録へこの設定を流用しない。`attestation: "enterprise"` には管理設定が必要である。

```javascript
const managedDeviceRegistration = {
    attestation: "direct"
};
```
