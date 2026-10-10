import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import de from './locales/de/translation.json'
import en from './locales/en/translation.json'
import es from './locales/es/translation.json'
import fr from './locales/fr/translation.json'
import it from './locales/it/translation.json'
import ptBR from './locales/pt-BR/translation.json'
import ptPT from './locales/pt-PT/translation.json'

// Same locale set as the Thyra platform (@thyra/i18n).
export const LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'it', label: 'Italiano' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
  { code: 'es', label: 'Español' },
  { code: 'pt-PT', label: 'Português (Portugal)' },
  { code: 'pt-BR', label: 'Português (Brasil)' },
] as const

export type LanguageCode = (typeof LANGUAGES)[number]['code']

const supportedLngs = LANGUAGES.map((l) => l.code)

function normalize(language: string): string {
  const exact = supportedLngs.find((c) => c.toLowerCase() === language.toLowerCase())
  if (exact) return exact
  const base = language.split('-')[0].toLowerCase()
  if (base === 'pt') return 'pt-PT'
  return supportedLngs.find((c) => c === base) ?? language
}

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      it: { translation: it },
      fr: { translation: fr },
      de: { translation: de },
      es: { translation: es },
      'pt-PT': { translation: ptPT },
      'pt-BR': { translation: ptBR },
    },
    fallbackLng: 'en',
    supportedLngs,
    nonExplicitSupportedLngs: false,
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      caches: ['localStorage'],
      lookupLocalStorage: 'thyra-language',
      convertDetectedLanguage: normalize,
    },
  })

i18n.on('languageChanged', (lng) => {
  document.documentElement.lang = lng
})
document.documentElement.lang = i18n.language

export default i18n

export { useTranslation, Trans } from 'react-i18next'
