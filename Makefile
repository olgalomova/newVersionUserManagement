NAME = user_management_app
DOCKER_COMPOSE = docker compose
PROJECT_NAME = newVersion
DB_VOLUME = $(PROJECT_NAME)_db_volume

all:
	@printf "Launching $(NAME)...\n"
	@$(DOCKER_COMPOSE) up -d
	@printf "Application started\n"

build:
	@printf "Building $(NAME)...\n"
	@$(DOCKER_COMPOSE) up -d --build
	@printf "Application built and started\n"

down:
	@printf "Stopping $(NAME)...\n"
	@$(DOCKER_COMPOSE) down

stop:
	@printf "Stopping containers...\n"
	@$(DOCKER_COMPOSE) stop

start:
	@printf "Starting containers...\n"
	@$(DOCKER_COMPOSE) start

restart:
	@printf "Restarting $(NAME)...\n"
	@$(DOCKER_COMPOSE) restart

re:
	@printf "Rebuilding $(NAME)...\n"
	@$(DOCKER_COMPOSE) down -v
	@$(DOCKER_COMPOSE) up -d --build
	@printf "Application rebuilt and started\n"

clean:
	@printf "Cleaning unused Docker images...\n"
	@docker image prune -f
	@printf "Clean completed\n"

fclean:
	@printf "Full clean (containers + volumes + images)...\n"
	@$(DOCKER_COMPOSE) down -v --rmi all
	@docker system prune -f
	@printf "Docker reset completed\n"

reset-db:
	@printf "Resetting database (removing DB volume only)...\n"
	@docker volume rm $(DB_VOLUME) 2>/dev/null || true
	@$(DOCKER_COMPOSE) up -d
	@printf "Database recreated\n"

ps:
	@$(DOCKER_COMPOSE) ps

logs:
	@$(DOCKER_COMPOSE) logs -f

.PHONY: all build down stop start restart re clean fclean reset-db ps logs
