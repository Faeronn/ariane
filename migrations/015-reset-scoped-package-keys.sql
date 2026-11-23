-- A package with a scope or Composer vendor now only takes a CPE of that publisher (the real run
-- mapped @types/ws to ws_project:ws): its matched keys are resolved again.
UPDATE `software_cpe`
  SET `status` = 'pending', `cpeName` = NULL, `cpeSynthetic` = 0, `versionNormalized` = 0, `cvesCheckedAt` = NULL
  WHERE `ecosystem` IS NOT NULL AND `vendor` <> '' AND `status` = 'matched';
