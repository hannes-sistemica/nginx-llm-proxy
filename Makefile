.PHONY: test install uninstall reload status help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Run integration tests with dummy backends
	@chmod +x test.sh
	@./test.sh

install: ## Create config.json from example if missing
	@test -f config.json || cp config.example.json config.json
	@echo "1. Edit config.json with your models and API key"
	@echo "2. Edit nginx.conf paths to point to this directory"
	@echo "3. sudo cp nginx.conf /etc/nginx/sites-enabled/llm-proxy"
	@echo "4. sudo nginx -t && sudo nginx -s reload"

uninstall: ## Remove nginx site config
	sudo rm -f /etc/nginx/sites-enabled/llm-proxy
	sudo nginx -s reload

reload: ## Reload config (via localhost admin endpoint)
	@curl -s http://localhost:4000/admin/reload

status: ## Show health and model list
	@echo "Health:"
	@curl -s http://localhost:4000/health
	@echo ""
	@echo "Models:"
	@curl -s http://localhost:4000/v1/models -H "Authorization: Bearer $$(python3 -c "import json; print(json.load(open('config.json'))['api_key'])")" 2>/dev/null || echo "(configure config.json first)"
