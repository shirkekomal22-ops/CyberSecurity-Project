from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/submit', methods=['POST'])
def submit():
    text = request.form['user_text']

    # store the text in a file
    with open("data.txt", "a") as f:
        f.write(text + "\n")

    return "Coming soon"

app.run(debug=True)