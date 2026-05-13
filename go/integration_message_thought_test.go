//go:build integration

package aun

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func thoughtPayloadTexts(t *testing.T, result map[string]any) []string {
	t.Helper()
	rawThoughts, _ := result["thoughts"].([]any)
	texts := make([]string, 0, len(rawThoughts))
	for _, raw := range rawThoughts {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		payload, _ := item["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		text, _ := payload["text"].(string)
		if text != "" {
			texts = append(texts, text)
		}
	}
	return texts
}

func TestIntegration_MessageThoughtGetKeepsDecryptedItems(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("thought-a-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("thought-b-%s.%s", rid, testIssuer()))
	contextValue := map[string]any{"type": "run", "id": fmt.Sprintf("thought-run-%s", rid)}

	expectedTexts := make([]string, 0, 9)
	for idx := 0; idx < 9; idx++ {
		text := fmt.Sprintf("thought-%d-%s", idx, rid)
		expectedTexts = append(expectedTexts, text)
		putRaw, err := alice.Call(ctx, "message.thought.put", map[string]any{
			"to":         bobAID,
			"context":    contextValue,
			"thought_id": fmt.Sprintf("mt-%s-%d", rid, idx),
			"payload":    map[string]any{"type": "thought", "text": text, "index": idx},
			"encrypt":    true,
		})
		if err != nil {
			t.Fatalf("message.thought.put idx=%d 失败: %v", idx, err)
		}
		putMap, _ := putRaw.(map[string]any)
		if int(toInt64(putMap["stored_count"])) < idx+1 {
			t.Fatalf("message.thought.put stored_count 异常 idx=%d result=%#v", idx, putMap)
		}
	}

	raw, err := bob.transport.Call(ctx, "message.thought.get", map[string]any{
		"sender_aid": aliceAID,
		"context":    contextValue,
	})
	if err != nil {
		t.Fatalf("raw message.thought.get 失败: %v", err)
	}
	rawMap, _ := raw.(map[string]any)
	rawThoughts, _ := rawMap["thoughts"].([]any)
	if rawMap["found"] != true || len(rawThoughts) != len(expectedTexts) {
		t.Fatalf("服务端原始 thoughts 条数异常: raw=%#v", rawMap)
	}

	resultRaw, err := bob.Call(ctx, "message.thought.get", map[string]any{
		"sender_aid": aliceAID,
		"context":    contextValue,
	})
	if err != nil {
		t.Fatalf("SDK message.thought.get 失败: %v", err)
	}
	resultMap, _ := resultRaw.(map[string]any)
	texts := thoughtPayloadTexts(t, resultMap)
	if !reflect.DeepEqual(texts, expectedTexts) {
		t.Fatalf("SDK 返回明文 thoughts 不匹配: texts=%#v expected=%#v result=%#v raw_count=%d",
			texts, expectedTexts, resultMap, len(rawThoughts))
	}

	repeatRaw, err := bob.Call(ctx, "message.thought.get", map[string]any{
		"sender_aid": aliceAID,
		"context":    contextValue,
	})
	if err != nil {
		t.Fatalf("重复 message.thought.get 失败: %v", err)
	}
	repeatMap, _ := repeatRaw.(map[string]any)
	repeatTexts := thoughtPayloadTexts(t, repeatMap)
	if !reflect.DeepEqual(repeatTexts, expectedTexts) {
		t.Fatalf("重复读取不应被 replay guard 消耗: texts=%#v result=%#v", repeatTexts, repeatMap)
	}
}
