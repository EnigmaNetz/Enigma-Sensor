package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

const envPrefix = "SENSOR_"

// ApplyEnvOverrides walks the Config struct using reflection and overrides
// field values from environment variables using the SENSOR_ prefix convention.
// Top-level fields use SENSOR_<JSON_TAG> and nested struct fields use
// SENSOR_<SECTION_JSON_TAG>_<FIELD_JSON_TAG>, all uppercased.
func ApplyEnvOverrides(cfg *Config) error {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		jsonTag := jsonTagName(fieldType)
		if jsonTag == "" {
			continue
		}

		if field.Kind() == reflect.Struct {
			// Nested struct: iterate its fields
			for j := 0; j < field.NumField(); j++ {
				nestedField := field.Field(j)
				nestedType := field.Type().Field(j)
				nestedTag := jsonTagName(nestedType)
				if nestedTag == "" {
					continue
				}

				envName := envPrefix + strings.ToUpper(jsonTag) + "_" + strings.ToUpper(nestedTag)
				val, ok := os.LookupEnv(envName)
				if !ok {
					continue
				}
				if err := setFieldFromString(nestedField, val); err != nil {
					return fmt.Errorf("env %s: %w", envName, err)
				}
			}
		} else {
			// Top-level leaf field
			envName := envPrefix + strings.ToUpper(jsonTag)
			val, ok := os.LookupEnv(envName)
			if !ok {
				continue
			}
			if err := setFieldFromString(field, val); err != nil {
				return fmt.Errorf("env %s: %w", envName, err)
			}
		}
	}

	return nil
}

// jsonTagName extracts the field name from a struct field's json tag,
// ignoring options like omitempty. Returns empty string if the tag is
// missing or set to "-".
func jsonTagName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	if idx := strings.Index(tag, ","); idx != -1 {
		tag = tag[:idx]
	}
	return tag
}

// setFieldFromString parses value and sets the reflect.Value accordingly.
// Supports string, int, int64, float64, and bool field types.
func setFieldFromString(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(f)
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(b)
	case reflect.Ptr:
		// Handle pointer types by allocating and setting the underlying value
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		return setFieldFromString(field.Elem(), value)
	default:
		return fmt.Errorf("unsupported type %s", field.Kind())
	}
	return nil
}
