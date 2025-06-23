//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.tidecloak.shared.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class JsonSorter {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static JsonNode parseAndSortArrays(JsonNode json) throws JsonProcessingException {
        if (json == null) {
            throw new IllegalArgumentException("Could not parse JSON");
        } else {
            return sortAllJsonArrays(json).node;
        }
    }

    public static JsonNode parseAndSortArrays(String json) throws JsonProcessingException {
        JsonNode rootNode = MAPPER.readTree(json);
        if (rootNode == null) {
            throw new IllegalArgumentException("Could not parse JSON");
        } else {
            return sortAllJsonArrays(rootNode).node;
        }
    }

    public static JsonNode parseAndSortArrays(byte[] json) throws IOException {
        JsonNode rootNode = MAPPER.readTree(json);
        if (rootNode == null) {
            throw new IllegalArgumentException("Could not parse JSON");
        } else {
            return sortAllJsonArrays(rootNode).node;
        }
    }

    private static Result sortAllJsonArrays(JsonNode node) {
        if (node.isArray()) {
            return sortJsonArray((ArrayNode)node);
        } else {
            return node.isObject() ? sortJsonObject((ObjectNode)node) : new Result(node, false);
        }
    }

    private static Result sortJsonArray(ArrayNode arrayNode) {
        List<Result> elementResults = new ArrayList();

        for(JsonNode item : arrayNode) {
            if (item == null) {
                elementResults.add(new Result(NullNode.instance, false));
            } else {
                Result childResult = sortAllJsonArrays(item);
                elementResults.add(childResult);
            }
        }

        List<String> keys = new ArrayList();

        for(Result r : elementResults) {
            JsonNode n = r.node;
            String key;
            if (n != null && !n.isNull()) {
                try {
                    key = MAPPER.writeValueAsString(n);
                } catch (JsonProcessingException var9) {
                    key = n.toString();
                }
            } else {
                key = "null";
            }

            keys.add(key);
        }

        boolean isSorted = true;

        for(int i = 1; i < keys.size(); ++i) {
            if (((String)keys.get(i - 1)).compareTo((String)keys.get(i)) > 0) {
                isSorted = false;
                break;
            }
        }

        boolean anyChildChanged = elementResults.stream().anyMatch((rx) -> rx.changed);
        if (isSorted && !anyChildChanged) {
            return new Result(arrayNode, false);
        } else {
            List<ElementWithKey> paired = new ArrayList();

            for(int i = 0; i < elementResults.size(); ++i) {
                paired.add(new ElementWithKey(((Result)elementResults.get(i)).node, (String)keys.get(i)));
            }

            paired.sort((a, b) -> a.key.compareTo(b.key));
            ArrayNode newArray = MAPPER.createArrayNode();

            for(ElementWithKey ewk : paired) {
                newArray.add((JsonNode)(ewk.node == null ? NullNode.instance : ewk.node.deepCopy()));
            }

            return new Result(newArray, true);
        }
    }

    private static Result sortJsonObject(ObjectNode objectNode) {
        boolean anyChange = false;
        List<PropertyResult> propertyResults = new ArrayList();
        Iterator<String> fieldNames = objectNode.fieldNames();

        while(fieldNames.hasNext()) {
            String key = (String)fieldNames.next();
            JsonNode value = objectNode.get(key);
            if (value == null) {
                propertyResults.add(new PropertyResult(key, NullNode.instance, false));
            } else {
                Result childResult = sortAllJsonArrays(value);
                propertyResults.add(new PropertyResult(key, childResult.node, childResult.changed));
                if (childResult.changed) {
                    anyChange = true;
                }
            }
        }

        if (!anyChange) {
            return new Result(objectNode, false);
        } else {
            ObjectNode newObject = MAPPER.createObjectNode();

            for(PropertyResult pr : propertyResults) {
                if (!pr.changed) {
                    newObject.set(pr.key, (JsonNode)(pr.node == null ? NullNode.instance : pr.node.deepCopy()));
                } else {
                    newObject.set(pr.key, pr.node);
                }
            }

            return new Result(newObject, true);
        }
    }

    private static class Result {
        final JsonNode node;
        final boolean changed;

        Result(JsonNode node, boolean changed) {
            this.node = node;
            this.changed = changed;
        }
    }

    private static class PropertyResult {
        final String key;
        final JsonNode node;
        final boolean changed;

        PropertyResult(String key, JsonNode node, boolean changed) {
            this.key = key;
            this.node = node;
            this.changed = changed;
        }
    }

    private static class ElementWithKey {
        final JsonNode node;
        final String key;

        ElementWithKey(JsonNode node, String key) {
            this.node = node;
            this.key = key;
        }
    }
}
