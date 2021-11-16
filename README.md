# superset 

Superset configuration for techaid https://superset.communitytechaid.org.uk/

## install 

```bash
# After initial configuration 
# Migrate local DB to latest
 docker exec -it superset superset db upgrade

# Setup roles 
docker exec -it superset superset init

# Load examples 
docker exec -it superset superset load_examples
```