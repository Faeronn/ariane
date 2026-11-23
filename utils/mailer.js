import nodemailer from 'nodemailer';
import logger from './logger.js';
import { renderEmail } from './notification-email.js';

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

// One item notification to the admins. Throws on failure: the caller keeps the item's alerts unsent
// and retries on its next tick.
export async function sendItemNotification(to, notification) {
	const { subject, html, text } = renderEmail(notification);
	const info = await transporter.sendMail({ from: senderAddress(), to, subject, html, text });
	logger.info({ messageId: info.messageId, recipients: to.length, item: `${notification.item.kind}:${notification.item.name}` }, 'Alert notification sent');
	return info;
}

// The transport in use, for tests that need to observe or fail deliveries.
export const getTransporter = () => transporter;

export { sendVerificationEmail };