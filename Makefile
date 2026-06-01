.PHONY: test install uninstall reload status help deploy deploy-nginx diff

# Local deploy config (host + secrets); see .deploy.env.example. Not committed.
-include .deploy.env

DEPLOY_HOST ?= root@192.168.1.125
PROXY_URL   ?= http://192.168.1.125:4000
ADMIN_PASSWORD ?=
WHISPER_API_KEY ?=
APP_DIR     ?= /opt/llm-proxy
NGINX_DST   ?= /etc/nginx/http.d/llm-proxy.conf
SSH         ?= ssh -o ConnectTimeout=8
SCP         ?= scp -q -o ConnectTimeout=8
APP_FILES   = llm-proxy.lua admin.html config.example.json README.md test.sh test-backend.py

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

test: ## Run integration tests with dummy backends
	@chmod +x test.sh
	@./test.sh

install: ## Create config.json from example if missing (fresh install)
	@test -f config.json || cp config.example.json config.json
	@echo "1. Edit config.json — set admin_password, api_keys, and models"
	@echo "2. Copy nginx.conf to the nginx include dir, e.g.:"
	@echo "     /etc/nginx/http.d/llm-proxy.conf   (Alpine/OpenResty)"
	@echo "     /etc/nginx/sites-enabled/llm-proxy (Debian nginx-extras)"
	@echo "3. sudo nginx -t && sudo nginx -s reload"

uninstall: ## Remove nginx site config
	sudo rm -f /etc/nginx/sites-enabled/llm-proxy
	sudo nginx -s reload

# ── Remote deploy (host has no git; workdir is the source of truth) ──────────

deploy: ## Push app files to the host + reload nginx (skips config.json/stats.json/nginx.conf)
	@echo "→ deploying app files to $(DEPLOY_HOST):$(APP_DIR)"
	$(SCP) $(APP_FILES) $(DEPLOY_HOST):$(APP_DIR)/
	$(SCP) -r static $(DEPLOY_HOST):$(APP_DIR)/
	@$(SSH) $(DEPLOY_HOST) 'nginx -t && nginx -s reload && echo "  nginx reloaded ✓"'

deploy-nginx: ## Render nginx.conf (inject WHISPER_API_KEY) + install + test + reload
	@test -n "$(WHISPER_API_KEY)" || { echo "ERROR: WHISPER_API_KEY unset — create .deploy.env"; exit 1; }
	@sed 's|<WHISPER_API_KEY>|$(WHISPER_API_KEY)|g' nginx.conf > /tmp/llm-proxy.conf.rendered
	@if grep -q '<WHISPER_API_KEY>' /tmp/llm-proxy.conf.rendered; then echo "ERROR: placeholder still present after render"; exit 1; fi
	@echo "→ installing $(NGINX_DST) on $(DEPLOY_HOST)"
	$(SCP) /tmp/llm-proxy.conf.rendered $(DEPLOY_HOST):$(NGINX_DST)
	@rm -f /tmp/llm-proxy.conf.rendered
	@$(SSH) $(DEPLOY_HOST) 'nginx -t && nginx -s reload && echo "  nginx reloaded ✓"'

diff: ## Show drift between workdir and the live host (app files + nginx.conf)
	@for f in llm-proxy.lua admin.html; do \
		printf "── %s ──\n" "$$f"; \
		$(SSH) $(DEPLOY_HOST) "cat $(APP_DIR)/$$f" > /tmp/host-$$f 2>/dev/null; \
		if diff -q /tmp/host-$$f "$$f" >/dev/null 2>&1; then echo "  in sync ✓"; else diff /tmp/host-$$f "$$f" | head -40; fi; \
		rm -f /tmp/host-$$f; \
	done
	@printf "── nginx.conf (rendered) vs host ──\n"; \
	if [ -n "$(WHISPER_API_KEY)" ]; then sed 's|<WHISPER_API_KEY>|$(WHISPER_API_KEY)|g' nginx.conf > /tmp/ngx-local.conf; else cp nginx.conf /tmp/ngx-local.conf; fi; \
	$(SSH) $(DEPLOY_HOST) "cat $(NGINX_DST)" > /tmp/ngx-host.conf 2>/dev/null; \
	if diff -q /tmp/ngx-host.conf /tmp/ngx-local.conf >/dev/null 2>&1; then echo "  in sync ✓"; else diff /tmp/ngx-host.conf /tmp/ngx-local.conf | head -40; fi; \
	rm -f /tmp/ngx-local.conf /tmp/ngx-host.conf

reload: ## Reload nginx on the host
	@$(SSH) $(DEPLOY_HOST) 'nginx -t && nginx -s reload && echo "reloaded ✓"'

status: ## Show host health + registered models
	@echo "Health:"; curl -s $(PROXY_URL)/health; echo
	@echo "Models:"; curl -s $(PROXY_URL)/admin/api/models -H "X-Admin-Password: $(ADMIN_PASSWORD)" 2>/dev/null || echo "(set ADMIN_PASSWORD in .deploy.env)"
