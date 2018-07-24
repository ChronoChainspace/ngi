/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package persist

import (
	"crypto/sha256"
	"time"

	"github.com/boltdb/bolt"
	"../ngi"
	"../tlv"
)

type cache struct {
	*bolt.DB
}

var (
	mainBucket = []byte("main")
)

func New(file string) (ngi.Cache, error) {
	db, err := bolt.Open(file, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &cache{DB: db}, nil
}

type entry struct {
	Data *ngi.Data `tlv:"2"`
	Time time.Time `tlv:"3"`
}

func (c *cache) Add(d *ngi.Data) {
	c.Update(func(tx *bolt.Tx) error {
		h := sha256.New()
		err := d.WriteTo(tlv.NewWriter(h))
		if err != nil {
			return err
		}

		b, err := tlv.Marshal(entry{
			Data: d,
			Time: time.Now(),
		}, 1)
		if err != nil {
			return err
		}

		bucket, err := tx.CreateBucketIfNotExists(mainBucket)
		if err != nil {
			return err
		}
		for _, component := range d.Name.Components {
			bucket, err = bucket.CreateBucketIfNotExists(component)
			if err != nil {
				return err
			}
		}
		return bucket.Put(h.Sum(nil), b)
	})
}

func (c *cache) Get(i *ngi.Interest) (match *ngi.Data) {
	sel := func(v []byte) bool {
		if v == nil {
			return false
		}
		var ent entry
		err := tlv.Unmarshal(v, &ent, 1)
		if err != nil {
			return false
		}
		if !i.Selectors.Match(ent.Data, i.Name.Len()) {
			return false
		}
		if i.Selectors.MustBeFresh && ent.Data.MetaInfo.FreshnessPeriod > 0 &&
			time.Since(ent.Time) > time.Duration(ent.Data.MetaInfo.FreshnessPeriod)*time.Millisecond {
			return false
		}
		match = ent.Data
		return true
	}

	var search func(bucket *bolt.Bucket) bool
	search = func(bucket *bolt.Bucket) bool {
		cursor := bucket.Cursor()

		var first, next func() ([]byte, []byte)
		if i.Selectors.ChildSelector == 0 {
			first = cursor.First
			next = cursor.Next
		} else {
			first = cursor.Last
			next = cursor.Prev
		}

		if i.Selectors.ChildSelector != 0 {
			for k, v := first(); k != nil; k, v = next() {
				if v != nil {
					continue
				}
				if search(bucket.Bucket(k)) {
					return true
				}
			}
		}

		for k, v := first(); k != nil; k, v = next() {
			if sel(v) {
				return true
			}
		}

		if i.Selectors.ChildSelector == 0 {
			for k, v := first(); k != nil; k, v = next() {
				if v != nil {
					continue
				}
				if search(bucket.Bucket(k)) {
					return true
				}
			}
		}

		return false
	}

	c.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(mainBucket)
		if bucket == nil {
			return nil
		}
		for _, component := range i.Name.Components {
			bucket = bucket.Bucket(component)
			if bucket == nil {
				return nil
			}
		}
		if len(i.Name.ImplicitDigestSHA256) != 0 {
			sel(bucket.Get(i.Name.ImplicitDigestSHA256))
			return nil
		}

		search(bucket)
		return nil
	})
	return
}
