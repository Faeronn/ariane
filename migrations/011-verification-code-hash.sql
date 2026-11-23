-- Verification codes are now stored as an HMAC (64 hex characters, the column already fits it).
-- Pending codes stored in clear can no longer be checked: they are dropped, and their users sign
-- up again as after an expired code.
DELETE FROM `verifications` WHERE `verificationCode` REGEXP '^[0-9]{6}$';
