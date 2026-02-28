![メインブランチ CI](https://img.shields.io/badge/%E3%83%A1%E3%82%A4%E3%83%B3%E3%83%96%E3%83%A9%E3%83%B3%E3%83%81_CI-passing-brightgreen)
![CodeQL セキュリティ分析](https://img.shields.io/badge/CodeQL_%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E5%88%86%E6%9E%90-passing-brightgreen)
![OpenSSF Scorecard](https://img.shields.io/badge/openssf_scorecard-8.2-brightgreen)
![OpenSSF Best Practices](https://img.shields.io/badge/openssf_best_practices-silver-silver)
![ライセンス](https://img.shields.io/badge/%E3%83%A9%E3%82%A4%E3%82%BB%E3%83%B3%E3%82%B9-MIT-green)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8)
![Gin](https://img.shields.io/badge/Gin-1.9-00ADD8)

# Contoso API ゲートウェイ

Go と Gin フレームワークで構築された、Contoso マイクロサービスアーキテクチャ向け高性能 API ゲートウェイです。

## 機能

- リクエストルーティングとロードバランシング
- JWT 認証と認可
- レート制限
- リクエスト/レスポンスのロギング
- ヘルスチェック
- TLS ターミネーション

## クイックスタート

```bash
go mod tidy
go run main.go
```

## 設定

`config.yaml` でサービスルーティングと認証設定を編集してください。

## ライセンス

このプロジェクトは [MIT ライセンス](LICENSE)の下で公開されています。

## セキュリティ

脆弱性を発見された場合は、[セキュリティポリシー](SECURITY.md)をご確認ください。
