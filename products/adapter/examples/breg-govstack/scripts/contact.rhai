// Public read projection and public-to-native write mappings for the example.

fn public_contact(source) {
    let contact = #{name: source.name, email: source.email};
    if source.note != () {
        contact.note = source.note;
    }
    contact
}

fn create_contact(source) {
    let native = source;
    native.jurisdiction = "zone-a";
    native
}

fn update_contact(source) {
    source
}
