from livereload import Server
from livereload import shell

app = Server()
# app.watch("src", shell("make build-docs"), delay=2)
app.watch("docs", shell("make build-docs"), delay=2)
app.serve(root="build/_html")
