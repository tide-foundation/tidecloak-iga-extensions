package org.tidecloak.models;

import java.util.ArrayList;
import java.util.List;

public class SecretKeys {
    public String activeVrk;
    public String pendingVrk;
    public String VZK;
    public List<String> history = new ArrayList<>();

    // Method to add a new entry to the history
    public void addToHistory(String newEntry) {
        history.add(newEntry);
    }
}