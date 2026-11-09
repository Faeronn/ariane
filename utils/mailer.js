import nodemailer from 'nodemailer';
import logger from './logger.js';

// SMTP options: implicit TLS when MAIL_SECURE=true (port 465), otherwise STARTTLS is required, so
// credentials and codes never travel in clear text. OAuth is not supported.
export function buildTransportOptions(environment = process.env) {
	const secure = environment.MAIL_SECURE === 'true';
	return {
		host: environment.MAIL_HOST,
		port: Number(environment.MAIL_PORT),
		secure,
		requireTLS: !secure,
		auth: { user: environment.MAIL_USER, pass: environment.MAIL_PASS }
	};
}

export const senderAddress = (environment = process.env) => environment.MAIL_FROM || environment.MAIL_USER;

// MAIL_TRANSPORT=json renders mails to JSON instead of sending them (tests).
const useJsonTransport = process.env.MAIL_TRANSPORT === 'json';
// eslint-disable-next-line sonarjs/no-clear-text-protocols -- the JSON transport never opens a network connection
const jsonTransporter = useJsonTransport ? nodemailer.createTransport({ jsonTransport: true }) : undefined;
// eslint-disable-next-line sonarjs/no-clear-text-protocols -- TLS is enforced by buildTransportOptions: implicit TLS or requireTLS (STARTTLS)
const transporter = jsonTransporter ?? nodemailer.createTransport(buildTransportOptions());

async function sendVerificationEmail(to, verificationCode) {
	const mailOptions = {
		from: senderAddress(),
		to: to,
		subject: 'Verifiez votre adresse Mail',
		html: `<div style="display:flex; align-items: center; justify-content: center; flex-direction: column; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
			<div class="email-header" style="background-color:#009ab1; color: white; padding: 20px 0px; width: 100%; text-align: center;">
				<h1>Verifiez votre adresse mail pour terminer votre inscription</h1>
			</div>
			<div class="email-body" style="background-color:#ffffff; color: black; padding: 20px; width: 600px; text-align: center;">
				<p>Bonjour,</p>
				<p>Merci de votre inscription à notre service. Nous sommes ravis de vous compter parmis nous.</p>
				<p>Pour compléter votre inscription, veuillez saisir le code de vérification ci-dessous dans l’application</p>
				<div style="font-size:32px; font-weight:bold; letter-spacing:6px; margin:20px 0; color:#009ab1;">${verificationCode}</div>
				<p>Ce code est valable pendant quelques minutes.</p>
				<p>Si vous n'êtes pas à l'origine de cette demande, veuillez ignorer cet e-mail.</p>
			</div>
			<div style="width: 100%; padding: 20px 0px; color: black; text-align: center;">
				<p style="margin: 0;">© Artemis-RD. Tous droits reservés.</p>
			</div>
		</div>`
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		logger.info({ messageId: info.messageId }, 'Verification email sent');
		return info;
	} catch (error) {
		logger.error(error, 'Failed to send verification email');
	}
}

const escapeHtml = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

function vulnerabilityLine({ cveID, severity, cvssScore, software, versionNormalized, platformDependent }) {
	const link = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveID)}`;
	const score = cvssScore === undefined ? 'score en attente' : `${severity} ${cvssScore}`;
	const affected = software.map(({ name, version }) => `${name} ${version}`).join(', ');
	const toVerify = versionNormalized || platformDependent ? ' <em>(à vérifier : correctif de distribution ou plateforme possible)</em>' : '';
	return `<li><a href="${escapeHtml(link)}">${escapeHtml(cveID)}</a> (${escapeHtml(score)}) : ${escapeHtml(affected)}${toVerify}</li>`;
}

// digest: { organization, total, shown, machines: [{ hostname, vulnerabilities: [...] }] }
export function buildAlertDigest(to, digest) {
	const machines = digest.machines.map(({ hostname, vulnerabilities }) => `<h3>${escapeHtml(hostname)}</h3><ul>${vulnerabilities.map(vulnerability => vulnerabilityLine(vulnerability)).join('')}</ul>`).join('');
	const more = digest.total > digest.shown ? `<p>${digest.total - digest.shown} autre(s) : voir GET /machines/:id/vulns.</p>` : '';
	return {
		from: senderAddress(),
		to,
		subject: `[Ariane] ${digest.total} nouvelle(s) vulnérabilité(s) - ${digest.organization}`,
		html: `<div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
			<p>Nouvelles vulnérabilités détectées sur les machines de ${escapeHtml(digest.organization)} :</p>
			${machines}${more}
		</div>`
	};
}

// Throws on failure: the caller keeps the alerts unsent and retries on its next tick.
export async function sendAlertDigest(to, digest) {
	const info = await transporter.sendMail(buildAlertDigest(to, digest));
	logger.info({ messageId: info.messageId, recipients: to.length }, 'Alert digest sent');
	return info;
}

// The transport in use, for tests that need to observe or fail deliveries.
export const getTransporter = () => transporter;

export { sendVerificationEmail };