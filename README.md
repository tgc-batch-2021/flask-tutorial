# flask-tutorial

## running guidelines

- Export env and app name, make sure you're in project root directory, that is flask-tutorial

```
export FLASK_ENV=development

export FLASK_APP=flaskr

flask run
```

## Initialize DB

- We've added a flask management command utility with click.
```
flask init-db
```

- check all the available management commands
```
flask --help
```

