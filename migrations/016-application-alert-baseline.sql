-- alertsBaselineAt: NULL until the first detection after the application's registration, whose
-- vulnerabilities (found only in this application) are recorded as already notified: registering
-- an application on a monitored machine does not alert everything it already had.
ALTER TABLE `applications` ADD COLUMN IF NOT EXISTS `alertsBaselineAt` datetime NULL DEFAULT NULL;
