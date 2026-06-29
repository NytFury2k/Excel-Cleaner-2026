def map_column_to_type(column_name, metadata):
    column_clean = column_name.strip().lower()

    for category, config in metadata.items():
        aliases = config.get("aliases", [])

        for alias in aliases:
            if column_clean == alias.lower():
                return config["type"]
            
    return None