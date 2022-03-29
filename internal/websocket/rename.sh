
#!/bin/bash

# By setting variables old and new, this script can be run to update the name
# of a chapter path for our imports.

myArray=("*.go" "go.mod" "DOCKERFILE" "Dockerfile" "Makefile" "*.yml" "*.yaml" "*.json")

for name in ${myArray[@]}; do
	find . -type f -name "$name" -exec sed -i '' "s/nhooyr.io\/websocket/github.com\/johnsiilver\/sshttp\/internal\/websocket/g" {} \;
done
