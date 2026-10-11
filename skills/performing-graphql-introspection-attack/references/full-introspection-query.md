# GraphQL Full Introspection Query and Schema Parsing

```python
GRAPHQL_URL = f"{TARGET}/graphql"
auth_headers = {**headers, "Authorization": "Bearer <token>"}

# Full introspection query to extract complete schema
FULL_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
    """
}

resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=FULL_INTROSPECTION)

if resp.status_code == 200:
    schema = resp.json()
    if "data" in schema and "__schema" in schema["data"]:
        print("[VULNERABLE] Full introspection enabled")
        types = schema["data"]["__schema"]["types"]

        # Categorize types
        custom_types = [t for t in types if not t["name"].startswith("__")]
        queries = schema["data"]["__schema"]["queryType"]
        mutations = schema["data"]["__schema"].get("mutationType")

        print(f"\nSchema Summary:")
        print(f"  Custom Types: {len(custom_types)}")
        print(f"  Query Type: {queries['name'] if queries else 'None'}")
        print(f"  Mutation Type: {mutations['name'] if mutations else 'None'}")

        # List all custom types and their fields
        for t in custom_types:
            if t.get("fields"):
                print(f"\n  Type: {t['name']}")
                for field in t["fields"]:
                    field_type = field["type"]["name"] or field["type"].get("ofType", {}).get("name", "")
                    print(f"    - {field['name']}: {field_type}")

        # Save schema for further analysis
        with open("graphql_schema.json", "w") as f:
            json.dump(schema, f, indent=2)
        print("\nSchema saved to graphql_schema.json")
    else:
        print("[SECURED] Introspection disabled or restricted")
        print(f"Response: {resp.text[:500]}")
else:
    print(f"Request failed: {resp.status_code}")
```
