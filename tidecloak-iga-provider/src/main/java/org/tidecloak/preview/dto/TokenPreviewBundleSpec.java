// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.dto;

import java.util.List;

public class TokenPreviewBundleSpec {
    public Long expectedActiveRev;
    public String expectedIgaMode; // "tide-iga" (true) or "base-iga" (false). Optional, compared against realm attr isIGAEnabled.

    public List<TokenPreviewSpec> items;
}
