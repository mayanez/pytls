dependencies:
	pip install --user requests ushlex pycrypto pyopenssl

docs:
	pydoc -w client/client.py server/server.py