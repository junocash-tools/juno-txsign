package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func TestTxPlanSchemaMatchesRuntimeLimits(t *testing.T) {
	schema := loadSchema(t, "txplan.v0.schema.json")
	properties := objectField(t, schema, "properties")

	coinType := objectField(t, properties, "coin_type")
	requireIntegers(t, field(t, coinType, "enum"), []int64{8133, 8134, 8135})
	requireInteger(t, objectField(t, properties, "account"), "maximum", 2_147_483_647)

	chain := objectField(t, properties, "chain")
	requireStrings(t, field(t, chain, "enum"), []string{
		"main", "mainnet", "regtest", "test", "testnet",
	})
	requireArrayContract(t, objectField(t, properties, "outputs"), 1, 200, false)
	requireArrayContract(t, objectField(t, properties, "notes"), 1, 200, false)

	allOf := arrayField(t, schema, "allOf")
	if len(allOf) != 1 {
		t.Fatalf("allOf length = %d, want 1", len(allOf))
	}
	oneOf := arrayField(t, asObject(t, allOf[0]), "oneOf")
	got := map[string]int64{}
	for _, branch := range oneOf {
		branchProperties := objectField(t, asObject(t, branch), "properties")
		coin := integerField(t, objectField(t, branchProperties, "coin_type"), "const")
		chainContract := objectField(t, branchProperties, "chain")
		if raw, ok := chainContract["const"]; ok {
			got[asString(t, raw)] = coin
			continue
		}
		for _, name := range asArray(t, field(t, chainContract, "enum")) {
			got[asString(t, name)] = coin
		}
	}
	want := map[string]int64{
		"main": 8133, "mainnet": 8133,
		"test": 8134, "testnet": 8134,
		"regtest": 8135,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain/coin_type bindings = %#v, want %#v", got, want)
	}

	definitions := objectField(t, schema, "$defs")
	note := objectField(t, definitions, "OrchardSpendNote")
	for _, required := range asArray(t, field(t, note, "required")) {
		if asString(t, required) == "note_id" {
			t.Fatal("diagnostic note_id must remain optional")
		}
	}
}

func TestPreparedTxSchemaMatchesRuntimeLimits(t *testing.T) {
	schema := loadSchema(t, "prepared_tx.v0.schema.json")
	properties := objectField(t, schema, "properties")

	outputs := objectField(t, properties, "orchard_output_action_indices")
	requireArrayContract(t, outputs, 1, 200, true)
	requireInteger(t, objectField(t, outputs, "items"), "maximum", 199)
	requireInteger(t, objectField(t, properties, "orchard_change_action_index"), "maximum", 199)

	required := objectField(t, properties, "orchard_required_spend_action_indices")
	requireArrayContract(t, required, 1, 200, true)
	requireInteger(t, objectField(t, required, "items"), "maximum", 199)

	defs := objectField(t, schema, "$defs")
	bundle := objectField(t, defs, "OrchardPcztBundleV0")
	actions := objectField(t, objectField(t, bundle, "properties"), "actions")
	requireArrayContract(t, actions, 2, 200, false)

	allOf := arrayField(t, schema, "allOf")
	if len(allOf) != 1 {
		t.Fatalf("allOf length = %d, want 1", len(allOf))
	}
	conditional := asObject(t, allOf[0])
	then := objectField(t, conditional, "then")
	thenOutputs := objectField(t, objectField(t, then, "properties"), "orchard_output_action_indices")
	requireInteger(t, thenOutputs, "maxItems", 199)
}

func TestExternalSigningSchemasMatchRuntimeLimits(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		arrayName  string
		definition string
	}{
		{
			name:       "signing requests",
			filename:   "signing_requests.v0.schema.json",
			arrayName:  "requests",
			definition: "SigningRequestV0",
		},
		{
			name:       "signature submissions",
			filename:   "spend_auth_sigs.v0.schema.json",
			arrayName:  "signatures",
			definition: "SpendAuthSigV0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := loadSchema(t, tt.filename)
			items := objectField(t, objectField(t, schema, "properties"), tt.arrayName)
			requireArrayContract(t, items, 1, 200, true)

			definition := objectField(t, objectField(t, schema, "$defs"), tt.definition)
			actionIndex := objectField(t, objectField(t, definition, "properties"), "action_index")
			requireInteger(t, actionIndex, "maximum", 199)
		})
	}
}

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve schema test path")
	}
	f, err := os.Open(filepath.Join(filepath.Dir(sourceFile), name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var schema map[string]any
	if err := decoder.Decode(&schema); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return schema
}

func requireArrayContract(t *testing.T, contract map[string]any, min, max int64, unique bool) {
	t.Helper()
	requireInteger(t, contract, "minItems", min)
	requireInteger(t, contract, "maxItems", max)
	if unique {
		got, ok := field(t, contract, "uniqueItems").(bool)
		if !ok || !got {
			t.Fatalf("uniqueItems = %#v, want true", contract["uniqueItems"])
		}
	}
}

func requireInteger(t *testing.T, object map[string]any, key string, want int64) {
	t.Helper()
	if got := integerField(t, object, key); got != want {
		t.Fatalf("%s = %d, want %d", key, got, want)
	}
}

func requireIntegers(t *testing.T, value any, want []int64) {
	t.Helper()
	values := asArray(t, value)
	got := make([]int64, 0, len(values))
	for _, value := range values {
		got = append(got, asInteger(t, value))
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("integers = %v, want %v", got, want)
	}
}

func requireStrings(t *testing.T, value any, want []string) {
	t.Helper()
	values := asArray(t, value)
	got := make([]string, 0, len(values))
	for _, value := range values {
		got = append(got, asString(t, value))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("strings = %v, want %v", got, want)
	}
}

func field(t *testing.T, object map[string]any, key string) any {
	t.Helper()
	value, ok := object[key]
	if !ok {
		t.Fatalf("missing field %q", key)
	}
	return value
}

func objectField(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	return asObject(t, field(t, object, key))
}

func arrayField(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	return asArray(t, field(t, object, key))
}

func integerField(t *testing.T, object map[string]any, key string) int64 {
	t.Helper()
	return asInteger(t, field(t, object, key))
}

func asObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value %#v is not an object", value)
	}
	return object
}

func asArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("value %#v is not an array", value)
	}
	return array
}

func asInteger(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("value %#v is not a JSON number", value)
	}
	integer, err := number.Int64()
	if err != nil {
		t.Fatalf("value %q is not an integer: %v", number, err)
	}
	return integer
}

func asString(t *testing.T, value any) string {
	t.Helper()
	stringValue, ok := value.(string)
	if !ok {
		t.Fatalf("value %#v is not a string", value)
	}
	return stringValue
}
