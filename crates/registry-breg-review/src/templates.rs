// SPDX-License-Identifier: Apache-2.0

//! The page templates, compiled once at startup with HTML autoescaping on
//! every template.

use minijinja::{AutoEscape, Environment};
use serde::Serialize;

pub(crate) const STYLESHEET: &str = include_str!("../static/review.css");

const TEMPLATES: [(&str, &str); 7] = [
    ("layout.html", include_str!("../templates/layout.html")),
    ("review.html", include_str!("../templates/review.html")),
    (
        "submitted.html",
        include_str!("../templates/submitted.html"),
    ),
    ("continue.html", include_str!("../templates/continue.html")),
    ("error.html", include_str!("../templates/error.html")),
    (
        "signed_out.html",
        include_str!("../templates/signed_out.html"),
    ),
    ("sign_in.html", include_str!("../templates/sign_in.html")),
];

/// One labelled value on the review page.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Item {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReviewPage<'a> {
    pub request_id: &'a str,
    pub entity_label: &'a str,
    pub target_label: &'a str,
    pub current: &'a [Item],
    pub proposed: &'a [Item],
    pub csrf: &'a str,
    /// The view the submit form confirms; `None` renders no form.
    pub view: Option<&'a str>,
    pub notice: bool,
}

pub(crate) struct Templates {
    environment: Environment<'static>,
}

impl Templates {
    pub(crate) fn load() -> Result<Self, minijinja::Error> {
        let mut environment = Environment::new();
        // Every value is escaped for HTML, whatever the template name says.
        environment.set_auto_escape_callback(|_| AutoEscape::Html);
        for (name, source) in TEMPLATES {
            environment.add_template(name, source)?;
        }
        let templates = Self { environment };
        // Render each page once so a template fault stops startup instead of
        // the first person who reaches it.
        templates.review(&ReviewPage {
            request_id: "00000000-0000-4000-8000-000000000000",
            entity_label: "",
            target_label: "",
            current: &[],
            proposed: &[],
            csrf: "",
            view: Some(""),
            notice: true,
        })?;
        templates.submitted("")?;
        templates.continue_to("00000000-0000-4000-8000-000000000000")?;
        templates.error("", "", "")?;
        templates.signed_out()?;
        templates.sign_in_again("00000000-0000-4000-8000-000000000000")?;
        Ok(templates)
    }

    pub(crate) fn review(&self, page: &ReviewPage<'_>) -> Result<String, minijinja::Error> {
        self.environment.get_template("review.html")?.render(page)
    }

    pub(crate) fn submitted(&self, csrf: &str) -> Result<String, minijinja::Error> {
        self.environment
            .get_template("submitted.html")?
            .render(minijinja::context! { csrf })
    }

    pub(crate) fn continue_to(&self, request_id: &str) -> Result<String, minijinja::Error> {
        self.environment
            .get_template("continue.html")?
            .render(minijinja::context! { request_id })
    }

    pub(crate) fn error(
        &self,
        code: &str,
        title: &str,
        message: &str,
    ) -> Result<String, minijinja::Error> {
        self.environment
            .get_template("error.html")?
            .render(minijinja::context! { code, title, message })
    }

    pub(crate) fn signed_out(&self) -> Result<String, minijinja::Error> {
        self.environment.get_template("signed_out.html")?.render(())
    }

    pub(crate) fn sign_in_again(&self, request_id: &str) -> Result<String, minijinja::Error> {
        self.environment
            .get_template("sign_in.html")?
            .render(minijinja::context! { request_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_is_escaped() {
        let templates = Templates::load().expect("templates compile");
        let hostile = [Item {
            label: "<b>label</b>".to_owned(),
            value: "\"><script>alert(1)</script>".to_owned(),
        }];
        let html = templates
            .review(&ReviewPage {
                request_id: "00000000-0000-4000-8000-000000000000",
                entity_label: "<i>entity</i>",
                target_label: "<u>target</u>",
                current: &hostile,
                proposed: &hostile,
                csrf: "\"csrf",
                view: Some("\"view"),
                notice: false,
            })
            .expect("render");
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("<b>"), "{html}");
        assert!(!html.contains("<i>"), "{html}");
        assert!(!html.contains("<u>"), "{html}");
        assert!(!html.contains("value=\"\"csrf"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }
}
