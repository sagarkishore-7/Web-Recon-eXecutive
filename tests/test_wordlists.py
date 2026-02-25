from wrx.wordlists import derive_context_words


def test_context_wordlist_derivation() -> None:
    words = derive_context_words(
        [
            "http://localhost:3000/login",
            "http://localhost:3000/api/users?sort=createdAt",
            "http://localhost:3000/dashboard/admin",
            "http://localhost:3000/assets/main.js#authRoute",
        ],
        max_words=50,
    )
    joined = " ".join(words)
    assert "login" in joined
    assert "api" in joined or "users" in joined
    assert len(words) > 3
