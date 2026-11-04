# v11 HTML静的品質検査：監査ノート

更新: 2026-11-04。対象は検証専用 `Anest-Group/anest-web-quality-test` のみ。**Anest One・Xserver・公開サイト・他のリポジトリには触れない。**

## 現在の確定状態
- PR #8 は Ready for review（Draft解除済み）だが、**main未反映・未マージ**。
- v11プレビューの自動テストは **115件すべて合格**。GitHub Actions `quality-preview-demo` run `41764889800`（PR head `58ce1fdd2fc8cd7c0a80bb98b6b76c900ed97c7d`）。その後の計画書更新については最新コミットのrunを都度確認する。
- 現在のv10 `trusted-demo-check` はPR #8の`qa/`変更を意図的に拒否する。**これは正しい保護挙動であり、v11の自動テスト不合格を意味しない。**
- 管理者の一時例外は、`quality-gate-main`（26438926）と`quality-gate-v10`（26445074）の両方で **0件**。いずれもActive、必須チェック維持。
- 実PRテスト：正常HTMLの PR #9 → 必須チェック2件合格、画像alt欠落の PR #10 → 必須チェック2件失敗。両PRとも未マージでクローズ。これは**現在のv10**を確認した結果で、v11をmainで確認した結果ではない。
- GitHub Rulesetの必要承認数は0件。ただし独立したコード監査は未実施。管理者がリスクを理解し、限定的な導入許可を判断する必要がある。

## 監査で改善したこと
1. 名前のないリンク・ボタン、空ラベル・`aria-labelledby`の空参照を検出。
2. `label for` の参照先不足を検出。
3. 主要な明示終了タグの不正な入れ子を検出。HTML5の省略可能な `head/body/html` 終了タグについては誤判定を解消。
4. `img alt`を使ったアクセシブルネームの判定を補強（直接の`img id`参照を含む）。
5. HTMLメタデータ、URL scheme、リンク内フラグメント等の限定的な静的検査。
6. v11は既存v10と一緒に**信頼済みbaseコミットの側**で実行する設計。`trusted-demo-check`ではv11のwarningもブロックする。

## 現在の結論
**v11は検証ブランチ上の候補版として維持し、まだ保護例外を再設定しない。**
現行のv10は正常/異常の両方のPR実測で動作している。検査器自体の更新には明示的な管理者例外が必要であり、その手順は `V11_UPGRADE_CHECKLIST_JA.md` に記載。

## v11の使い方（候補ブランチでのみ）
```bash
python3 -m unittest discover -s qa -p 'test_*.py' -t . -v
python3 qa/site_audit_v11.py site/index.html --json
python3 qa/site_audit_v11.py site/index.html --fail-on-warning --json
```

## 対応できていない領域
ブラウザでの見え方、CSS崩れ、JSによるDOM操作、Lighthouse・速度、HTML5完全検証、WCAG完全適合、リンク先到達確認、フォーム送信、脆弱性診断、社員運用。静的検査の誤判定や見逃しも残り得る。

**115件合格は単体テストの合格件数であり、Web品質や安全性の点数ではない。**
