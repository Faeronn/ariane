function sanitizeInput(input) {
	if (typeof input === 'string') return input.replaceAll(/[<>'"]/g, '');
	return input;
}

export default sanitizeInput;
