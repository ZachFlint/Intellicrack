import intellicrack_hexcore as h

doc = h.HexDocument()
transforms = doc.list_transforms()
print("count:", len(transforms))
for t in transforms[:50]:
    print(repr(t))
