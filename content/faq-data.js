/*
 * The FAQ, once.
 *
 * build.js renders BOTH the visible page and the FAQPage JSON-LD from this
 * array. Google's structured-data guidelines require the marked-up questions
 * and answers to match what a visitor can actually read on the page, and the
 * usual way that breaks is somebody editing the copy and forgetting the
 * schema, or the other way round. With one source there is nothing to forget.
 *
 * Answers are deliberately short — 40 to 60 words is the length a featured
 * snippet or a voice assistant will read out whole. Anything longer gets
 * truncated somewhere unhelpful.
 *
 * `a` is plain text with no markup: it goes into JSON-LD as a string, and any
 * HTML in it would either be escaped into nonsense or break the block.
 */
export const FAQ = [
  {
    q: 'Do you charge a call-out fee?',
    a: 'Yes — there is a £45 call-out charge, confirmed before you book, and it is the same wherever you are inside the area we cover. Tyre prices are shown per tyre and already include fitting. For any other work the full price is confirmed with you before anything starts.',
  },
  {
    q: 'What areas do you cover?',
    a: 'Bridport and West Dorset, roughly a forty-mile radius from Bridport. That takes in Dorchester, Weymouth, Portland, Lyme Regis, Charmouth, Beaminster, Burton Bradstock, Axminster and Crewkerne. If you are near the edge of that, ring and ask — you will get a straight answer.',
  },
  {
    q: 'Can you fit tyres at my home or workplace?',
    a: 'Yes. New tyres are supplied and fitted at your home, your work or at the roadside. One tyre takes about twenty minutes once we are with you, a full set usually under an hour. The old tyres are taken away and disposed of.',
  },
  {
    q: 'How do I find my tyre size?',
    a: 'It is printed on the sidewall of the tyre already on the car, as three numbers like 195/65 R15 — width in millimetres, profile, then rim diameter in inches. Enter that on our home page and you get live prices for that size with fitting included.',
  },
  {
    q: 'Do you offer 24 hour breakdown and recovery?',
    a: 'Yes. Breakdown and recovery runs twenty-four hours, including nights and weekends. Servicing, tyre fitting and booked repairs run to normal working hours. For a breakdown, phone rather than using the booking form — it is always faster.',
  },
  {
    q: 'Can you service my car at my house?',
    a: 'Yes. Interim and full services are carried out on your driveway or in your work car park. Anything found is explained at the time, with a price, and nothing beyond the service is done without you agreeing to it first.',
  },
  {
    q: 'Will a mobile service affect my manufacturer warranty?',
    a: 'No. A manufacturer warranty is not tied to main-dealer servicing. As long as the car is serviced to the manufacturer schedule with parts of matching quality and the work is recorded, the warranty stands. Your service record is stamped and you keep the invoice.',
  },
  {
    q: 'How do I pay, and when?',
    a: 'Payment is taken on site when the job is finished, by card or cash. Nothing is taken when you book. You are told the full price before any work starts, so the figure at the end is the figure you agreed.',
  },
  {
    q: 'What happens if you cannot fix it at the roadside?',
    a: 'The vehicle is recovered rather than left — to your home, to a garage, or to us. Recovery is priced on distance and what is involved, and you are told that figure before anything is loaded onto the truck.',
  },
  {
    q: 'How long will you be?',
    a: 'You are given an actual time when you call, not a window of a whole day. Once the van sets off you can follow it on a live map with a moving ETA, so you can see how far away help is rather than guessing.',
  },
  {
    q: 'My engine management light is on. Is the car safe to drive?',
    a: 'It depends what set it off, and the light alone does not say. We read the fault code at your address and explain what it means, how urgent it is and whether the car is safe in the meantime. You are given the code itself as well.',
  },
  {
    q: 'Do I need to be there while you work?',
    a: 'Not for the whole job, as long as we can reach the vehicle and have the keys. Say when you book how you want to hand them over. For anything where a decision might be needed, being contactable by phone is enough.',
  },
  {
    q: 'Can you fit tyres I have already bought?',
    a: 'Yes. Tyres you have bought yourself can be fitted at your address on the same call-out basis. Mention it when you book so the right equipment comes out with the van.',
  },
  {
    q: 'Do you work on vans and 4x4s?',
    a: 'Yes — cars, vans and 4x4s. Fleet and work vehicles can be booked out of hours where that keeps them earning during the day. Ask when you book and a time will be found.',
  },
  {
    q: 'How do I book?',
    a: 'Book online at cousinsmechanicalservices.co.uk and pick a service, a date and a time, or call 07925 340977. Booking online gives you a reference, a confirmation by text and email, and live tracking on the day.',
  },
];
