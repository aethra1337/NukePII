# NukePII shortcuts (Windows: `python -m` targets work in PowerShell too).
.PHONY: install lint run openapi docker-build docker-run

install:
	pip install -r requirements.txt
	pip install -e .

lint:
	ruff check nukepii
	ruff format --check nukepii

run:
	python nukepii/web/app.py

openapi:
	python -m nukepii.cli.main openapi --out openapi/openapi.json

docker-build:
	docker build -t nukepii .

docker-run:
	docker run --rm -p 5000:5000 nukepii
