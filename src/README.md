olx-backend/
├── Cargo.toml
├── .env                     # Local secrets (DATABASE_URL, JWT_SECRET)
├── .gitignore
├── migrations/              # SQLx database migration files (.sql)
└── src/
    ├── main.rs              # Entry point: loads config, DB pool, starts server
    ├── config.rs            # Reads environment variables into a struct
    ├── error.rs             # Custom AppError enum implementing IntoResponse
    ├── state.rs             # Shared AppState (PgPool, config) passed to routes
    └── modules/
        ├── mod.rs           # Combines all module routers into one API router
        ├── auth/            # User registration, OTP, JWT middleware
        │   ├── mod.rs
        │   ├── routes.rs    # HTTP endpoints (/register, /login)
        │   ├── service.rs   # Business logic & password/OTP verification
        │   └── models.rs    # Request/Response structs & DB rows
        ├── listings/        # Classified ads CRUD, search, location filters
        │   ├── mod.rs
        │   ├── routes.rs
        │   ├── service.rs
        │   └── models.rs
        └── chat/            # WebSocket handler & message persistence
            ├── mod.rs
            ├── routes.rs
            └── models.rs