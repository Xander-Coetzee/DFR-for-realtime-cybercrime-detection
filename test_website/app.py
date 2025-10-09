from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/no-threat")
def no_threat():
    return render_template("no_threat.html")


@app.route("/medium-threat")
def medium_threat():
    return render_template("medium_threat.html")


@app.route("/high-threat")
def high_threat():
    return render_template("high_threat.html")


if __name__ == "__main__":
    app.run(debug=True)
