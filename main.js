import authRouter from './routes/auth.js';
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();
const app = express();
app.disable("x-powered-by");
const port = process.env.PORT;

//TODO : Security hardening with limiters, IP filters ect
//Why not using an Interceptor for that
app.use((request, response, next) => {
	express.json()(request, response, error => {
		if (error) return response.status(400).send({ message: 'Error : Bad JSON formatting.' });

		return next();
	});
});

// Routes
app.use('/auth', cors(), authRouter);

app.listen(port, () => { console.log(`Server running on http://localhost:${port}`); });
