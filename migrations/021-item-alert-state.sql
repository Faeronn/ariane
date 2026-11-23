-- Alerts per item: a machine (its installed programs) and each application (its packages) are
-- items of their own, each with its new, resolved and sent CVEs. Replaces the per-machine state.
CREATE TABLE IF NOT EXISTS `item_cve_state` (
  `itemType` enum('machine','application') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `itemID` int NOT NULL,
  `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `firstSeenAt` datetime NOT NULL,
  `resolvedAt` datetime NULL DEFAULT NULL,
  `emailSentAt` datetime NULL DEFAULT NULL,
  `webhookSentAt` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`itemType`, `itemID`, `cveID`) USING BTREE,
  INDEX `idx_email_unsent`(`emailSentAt`, `resolvedAt`) USING BTREE,
  INDEX `idx_webhook_unsent`(`webhookSentAt`, `resolvedAt`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

ALTER TABLE `applications` ADD COLUMN IF NOT EXISTS `alertsCheckedAt` datetime NULL DEFAULT NULL;

-- Every item takes a fresh baseline at the next detection (its current CVEs recorded as sent):
-- no alert storm at the switch. Alerts still unsent in the old state are not carried over.
UPDATE `machines` SET `alertsBaselineAt` = NULL;
UPDATE `applications` SET `alertsBaselineAt` = NULL;
DROP TABLE IF EXISTS `machine_cve_state`;
