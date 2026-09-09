.PHONY: help lab-up lab-down lab-scan backend frontend test clean

help:
	@echo "NETVA — Network-Level Vulnerability Assessment Tool"
	@echo ""
	@echo "  make lab-up        Start the Docker lab network"
	@echo "  make lab-down      Stop and remove lab containers"
	@echo "  make lab-scan      Run nmap scan from attacker container"
	@echo "  make backend       Install deps and start FastAPI backend"
	@echo "  make frontend      Install deps and start React frontend"
	@echo "  make test          Run end-to-end pipeline test"
	@echo "  make clean         Remove generated files"

lab-up:
	cd lab && docker-compose up -d --build
	@echo "Lab network started. Containers:"
	@docker ps --filter "name=lab_" --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"

lab-down:
	cd lab && docker-compose down -v

lab-scan:
	docker exec lab_attacker nmap -sV -sC -oX /tmp/lab_scan.xml 10.10.0.0/24 10.20.0.0/24
	docker cp lab_attacker:/tmp/lab_scan.xml ./tests/fixtures/lab_nmap_scan.xml
	@echo "Scan saved to tests/fixtures/lab_nmap_scan.xml"

backend:
	cd backend && pip install -r requirements.txt
	cd backend && uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd frontend && npm install && npm run dev

test:
	cd $(shell pwd) && python -m pytest tests/ -v
	cd $(shell pwd) && python tests/test_e2e_pipeline.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf frontend/node_modules frontend/dist
