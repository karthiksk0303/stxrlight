from flask import Flask, request, jsonify, render_template
import jwt

app = Flask(__name__)

FLAG = "ROOT@KNU11{STRXX_L1GHttt_Pay4lug4}"
SECRET = "starlight-demo-secret"

def auth_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        try:
            # Intentional JWT verification flaw for this CTF.
            claims = jwt.decode(
                token[7:],
                options={
                    "verify_signature": False,
                    "verify_exp": False
                },
                algorithms=["HS256"]
            )
        except Exception:
            return jsonify({"error": "Invalid token"}), 401

        request.claims = claims
        return fn(*args, **kwargs)

    return wrapper


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /internal-docs"


@app.route("/internal-docs")
def docs():
    return render_template("docs.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    if data.get("username") != "stargazer":
        return jsonify({"error": "Invalid credentials"}), 401

    if data.get("password") != "nightfall":
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {"sub": "stargazer", "role": "researcher"},
        SECRET,
        algorithm="HS256"
    )

    return jsonify({"token": token})


@app.route("/api/profile")
@auth_required
def profile():
    return jsonify({
        "username": request.claims.get("sub"),
        "role": request.claims.get("role")
    })


@app.route("/api/archive")
@auth_required
def archive():
    if request.claims.get("role") != "admin":
        return jsonify({"error": "Admin role required"}), 403

    return jsonify({"flag": FLAG})


if __name__ == "__main__":
    app.run()
