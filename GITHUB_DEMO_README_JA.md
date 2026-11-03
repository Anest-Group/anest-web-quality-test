GitHub品質ゲート導入検証（本番用ではありません）

このリポジトリは検証専用です。Anest Oneや他社の本番コード、APIキーは含めません。

- GitHub ActionsでHTMLの簡易チェックを動かします。96項目の品質認定ではありません。
- 読み取り専用権限・秘密情報なし・デプロイなしです。
- PRはDraftとして作成し、mainにマージしません。
- GitHubのプランに対応した保護ルールの設定前は、不合格PRのマージ禁止は強制されません。
- 検査用スクリプトをPR作成者が変更できるため、この簡易チェックだけを本番の独立品質ゲートとして信用してはいけません。

ローカル確認: python3 qa/demo_gate.py site/index.html と python3 -m unittest discover -s qa -p test_*.py -t . -v
