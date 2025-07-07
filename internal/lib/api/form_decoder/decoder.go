package form_decoder

import (
	"net/http"
	"reflect"
)

func DecodeForm(r *http.Request, dst any) error {
	err := r.ParseForm()
	if err != nil {
		return err
	}
	return parseForm(dst, r.PostForm)
}

func parseForm(dst any, values map[string][]string) error {
	dstVal := reflect.ValueOf(dst).Elem()
	dstType := dstVal.Type()

	for i := 0; i < dstType.NumField(); i++ {
		field := dstType.Field(i)
		formName := field.Tag.Get("form")
		if formName == "" {
			continue
		}

		valuesForKey := values[formName]
		if len(valuesForKey) == 0 {
			continue
		}

		fieldVal := dstVal.Field(i)
		if fieldVal.Kind() == reflect.String {
			fieldVal.SetString(valuesForKey[0])
		}
	}

	return nil
}
