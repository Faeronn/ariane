-- Alert settings per organization: severity threshold, email on/off, optional Slack or Discord webhook.
ALTER TABLE `organizations`
  ADD COLUMN IF NOT EXISTS `alertMinSeverity` enum('LOW','MEDIUM','HIGH','CRITICAL') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'HIGH',
  ADD COLUMN IF NOT EXISTS `alertEmailEnabled` tinyint(1) NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS `alertWebhookKind` enum('slack','discord') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `alertWebhookUrl` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL;
